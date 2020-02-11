// Copyright 2018 The Grin Developers
// Modifications Copyright 2019 The Gotts Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod common;

use self::core::core::verifier_cache::{LruVerifierCache, VerifierCache};
use self::core::core::{Output, OutputFeaturesEx};
use self::core::libtx::{build, proof};
use self::keychain::{ExtKeychain, Identifier, Keychain};
use self::util::secp::PublicKey;
use self::util::RwLock;
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_util as util;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::u32;

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

#[test]
fn test_verifier_cache_unlocker() {
	let cache = verifier_cache();

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = proof::ProofBuilder::new(&keychain, &Identifier::zero());

	let key_id = ExtKeychain::derive_key_id(4, u32::MAX, u32::MAX, 0, 0);
	let w: i64 = thread_rng().gen();

	let recipient_prikey = keychain.derive_key(&key_id).unwrap();
	let recipient_pubkey = PublicKey::from_secret_key(keychain.secp(), &recipient_prikey).unwrap();
	let (commit, locker, ephemeral_key_q) =
		proof::create_output_locker(&keychain, 5, &recipient_pubkey, w, 1, true).unwrap();
	let _out = Output {
		features: OutputFeaturesEx::SigLocked { locker },
		commit,
		value: 5,
	};

	let mut input_build_parm: Vec<build::InputExBuildParm> = vec![];
	input_build_parm.push(build::InputExBuildParm {
		value: 5,
		w,
		key_id,
		ephemeral_key: ephemeral_key_q,
		p2pkh: locker.p2pkh,
	});
	let mut parts = vec![];
	parts.push(build::siglocked_input(input_build_parm));

	let (tx, _blind) = build::partial_transaction(parts, &keychain, &builder).unwrap();
	let inputs = tx.inputs_ex();

	// Check our output is not verified according to the cache.
	{
		let mut cache = cache.write();
		let unverified = cache.filter_unlocker_unverified(inputs);
		assert_eq!(&unverified, inputs);
	}

	// Add our inputs to the cache.
	{
		let mut cache = cache.write();
		cache.add_unlocker_verified(&inputs.clone());
	}

	// Check it shows as verified according to the cache.
	{
		let mut cache = cache.write();
		let unverified = cache.filter_unlocker_unverified(inputs);
		assert_eq!(unverified, vec![]);
	}
}
