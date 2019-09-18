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

//! Transaction integration tests

pub mod common;

use self::core::core::{Output, OutputFeaturesEx};
use self::core::libtx::proof;
use self::core::ser;
use self::keychain::{ExtKeychain, Keychain};
use gotts_core as core;
use gotts_keychain as keychain;
use rand::{thread_rng, Rng};

#[test]
fn test_output_ser_deser() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let w: u64 = thread_rng().gen();
	let commit = keychain.commit(w, &key_id).unwrap();
	let builder = proof::ProofBuilder::new(&keychain);
	let spath = proof::create_secured_path(&keychain, &builder, w, &key_id, commit);

	let out = Output {
		features: OutputFeaturesEx::Plain { spath },
		commit,
		value: 5,
	};

	let mut vec = vec![];
	ser::serialize_default(&mut vec, &out).expect("serialized failed");
	let dout: Output = ser::deserialize_default(&mut &vec[..]).unwrap();

	assert_eq!(dout.features, out.features);
	assert_eq!(dout.commit, out.commit);
	assert_eq!(dout.value, out.value);
}
