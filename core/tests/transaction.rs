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

use self::core::core::{Output, OutputFeaturesEx, OutputI, OutputII};
use self::core::libtx::proof;
use self::core::ser;
use self::keychain::{ExtKeychain, Keychain};
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_util::secp::key::{PublicKey, SecretKey};
use gotts_util::to_hex;
use rand::{thread_rng, Rng};

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
