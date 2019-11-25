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

use self::core::core::transaction::Weighting;
use self::core::core::verifier_cache::{LruVerifierCache, VerifierCache};
use self::core::core::{Output, OutputEx, OutputFeaturesEx, OutputI, OutputII};
use self::core::libtx::{build, proof};
use self::core::ser;
use self::keychain::{ExtKeychain, Keychain};
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_util::init_test_logger;
use gotts_util::secp::key::{PublicKey, SecretKey};
use gotts_util::secp::pedersen::Commitment;
use gotts_util::{to_hex, RwLock};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::sync::Arc;
use std::u32;

#[test]
fn test_output_ser_deser() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let w: i64 = thread_rng().gen();
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

#[test]
fn test_output_std_hash() {
	use std::collections::hash_map::DefaultHasher;
	use std::hash::{Hash, Hasher};

	let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let w: i64 = 100;
	let commit = keychain.commit(w, &key_id).unwrap();
	let builder = proof::ProofBuilder::new(&keychain);
	let spath = proof::create_secured_path(&keychain, &builder, w, &key_id, commit);

	let out = Output {
		features: OutputFeaturesEx::Plain { spath },
		commit,
		value: 5,
	};
	let out_i = OutputI::from_output(&out).unwrap();

	let recipient_prikey = SecretKey::from_slice(&[2; 32]).unwrap();
	let recipient_pubkey = PublicKey::from_secret_key(keychain.secp(), &recipient_prikey).unwrap();
	let (_, locker, _) =
		proof::create_output_locker(&keychain, 5, &recipient_pubkey, w, 1, true).unwrap();
	let out_ii = OutputII {
		value: 5,
		id: out.id(),
		locker,
	};

	let mut vec = vec![];
	ser::serialize_default(&mut vec, &out).expect("serialized failed");
	let dout: Output = ser::deserialize_default(&mut &vec[..]).unwrap();
	assert_eq!(dout.value, out.value);
	assert_eq!(70, vec.len());
	println!("\nOutput   Ser: {}", to_hex(vec.clone()));

	vec.clear();
	ser::serialize_default(&mut vec, &out_i).expect("serialized failed");
	let dout_i: OutputI = ser::deserialize_default(&mut &vec[..]).unwrap();
	assert_eq!(dout_i.value, out.value);
	assert_eq!(70, vec.len());
	println!("\nOutputI  Ser: {}", to_hex(vec.clone()));

	vec.clear();
	ser::serialize_default(&mut vec, &out_ii).expect("serialized failed");
	let dout_ii: OutputII = ser::deserialize_default(&mut &vec[..]).unwrap();
	assert_eq!(dout_ii.value, out.value);
	assert_eq!(119, vec.len());
	println!("\nOutputII Ser: {}", to_hex(vec.clone()));

	// Because ::std::hash::Hash use serialize_default,
	// all 3 types: Output, OutputI, and OutputII will have different Hash result.
	//
	let mut hasher = DefaultHasher::new();
	out.id().hash(&mut hasher);
	assert_eq!("ed8fc1049eacbf86", format!("{:x}", hasher.finish()));

	let mut hasher = DefaultHasher::new();
	out.hash(&mut hasher);
	assert_eq!("3b9c793f9b74680f", format!("{:x}", hasher.finish()));

	let mut hasher = DefaultHasher::new();
	out_i.hash(&mut hasher);
	assert_eq!("3d6c2e69d0335596", format!("{:x}", hasher.finish()));

	let mut hasher = DefaultHasher::new();
	out_ii.hash(&mut hasher);
	assert_eq!("d506ab1940606574", format!("{:x}", hasher.finish()));
}

#[test]
fn test_output_blake2b_hash() {
	use gotts_core::core::hash::{Hash, Hashed};

	let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let w: i64 = 100;
	let commit = keychain.commit(w, &key_id).unwrap();
	let builder = proof::ProofBuilder::new(&keychain);
	let spath = proof::create_secured_path(&keychain, &builder, w, &key_id, commit);

	let out = Output {
		features: OutputFeaturesEx::Plain { spath },
		commit,
		value: 5,
	};
	let out_i = OutputI::from_output(&out).unwrap();

	let recipient_prikey = SecretKey::from_slice(&[2; 32]).unwrap();
	let recipient_pubkey = PublicKey::from_secret_key(keychain.secp(), &recipient_prikey).unwrap();
	let (_, locker, _) =
		proof::create_output_locker(&keychain, 5, &recipient_pubkey, w, 1, true).unwrap();
	let out_ii = OutputII {
		value: 5,
		id: out.id(),
		locker,
	};

	let mut vec = vec![];
	ser::serialize_default(&mut vec, &out).expect("serialized failed");
	let dout: Output = ser::deserialize_default(&mut &vec[..]).unwrap();

	let mut vec_i = vec![];
	ser::serialize_default(&mut vec_i, &out_i).expect("serialized failed");
	let dout_i: OutputI = ser::deserialize_default(&mut &vec_i[..]).unwrap();

	let mut vec_ii = vec![];
	ser::serialize_default(&mut vec_ii, &out_ii).expect("serialized failed");
	let dout_ii: OutputII = ser::deserialize_default(&mut &vec_ii[..]).unwrap();

	// Test: among all 3 types: Output, OutputI, and OutputII, we define same Hash
	// for all of them:
	// 1. Only the OutputIdentifier is used for Hash.
	// 2. All 3 types (Output, OutputI, OutputII) have same Hash result.
	//
	let hash_str = "64dec897674fc86509d258b0174ab626d483bbbe943dbcb68e509009a279a2a7";
	let hash_result = Hash::from_hex(hash_str).unwrap();
	assert_eq!(hash_result, out.id().hash());
	assert_eq!(hash_result, dout.hash());
	assert_eq!(hash_result, dout_i.hash());
	assert_eq!(hash_result, dout_ii.hash());

	// The full serialized vector hash are different
	assert_eq!(
		Hash::from_hex("f1a4f13694aae656bbbd7c7b50361f88fc2c02086f7ee55f4924a99087a352ed").unwrap(),
		vec.hash()
	);
	assert_eq!(
		Hash::from_hex("a5134feff2bc8a6625a26115220f8ce216be291586514c3aaf9f7850f97b05f3").unwrap(),
		vec_i.hash()
	);
	assert_eq!(
		Hash::from_hex("4504a1f255a39cd67de0a56ec8fc4abe6f8556451399b62a7c3a466884d9a3d0").unwrap(),
		vec_ii.hash()
	);
}

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

#[test]
fn test_siglocked_input_validate() {
	init_test_logger();

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = proof::ProofBuilder::new(&keychain);

	let key_id = ExtKeychain::derive_key_id(4, u32::MAX, u32::MAX, 0, 0);
	let mut w: i64 = thread_rng().gen();
	w = w / 4;

	let recipient_prikey = keychain.derive_key(&key_id).unwrap();
	let recipient_pubkey = PublicKey::from_secret_key(keychain.secp(), &recipient_prikey).unwrap();
	let (commit, locker, ephemeral_key_q) =
		proof::create_output_locker(&keychain, 6, &recipient_pubkey, w, 1, true).unwrap();
	let out = Output {
		features: OutputFeaturesEx::SigLocked { locker },
		commit,
		value: 6,
	};
	println!(
		"A SigLocked output: {}",
		serde_json::to_string_pretty(&out).unwrap()
	);

	// build an InputEx with InputUnlocker to spend above output
	let mut input_build_parm: Vec<build::InputExBuildParm> = vec![];
	input_build_parm.push(build::InputExBuildParm {
		value: 6,
		w,
		key_id,
		ephemeral_key: ephemeral_key_q,
		p2pkh: locker.p2pkh,
	});
	let mut parts = vec![];
	parts.push(build::siglocked_input(input_build_parm));

	// build a change output
	let mut change_w: i64 = thread_rng().gen();
	change_w = change_w / 4;
	let change_key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	parts.push(build::output(2, Some(change_w), change_key_id));

	// build the receiver output
	let receiver_w = w - change_w;
	let receiver_key_id = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	parts.push(build::output(3, Some(receiver_w), receiver_key_id));

	// build the kernel
	parts.push(build::with_fee(1));

	let tx = build::transaction(parts, &keychain, &builder).unwrap();
	let vc = verifier_cache();

	let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
	complete_inputs.insert(
		out.commit.clone(),
		OutputEx {
			output: out,
			height: 0,
			mmr_index: 1,
		},
	);
	println!(
		"InputEx with InputUnlocker to spend a SigLocked output: {}",
		serde_json::to_string_pretty(&tx.body.inputs).unwrap()
	);
	assert_eq!(
		tx.validate(
			Weighting::AsTransaction,
			vc.clone(),
			Some(&complete_inputs),
			1
		)
		.is_ok(),
		true
	);
}
