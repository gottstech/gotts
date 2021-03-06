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

//! Core tests

pub mod common;

use self::core::core::block::BlockHeader;
use self::core::core::block::Error::KernelLockHeight;
use self::core::core::hash::{Hashed, ZERO_HASH};
use self::core::core::verifier_cache::{LruVerifierCache, VerifierCache};
use self::core::core::{aggregate, deaggregate, KernelFeatures, OutputEx, Transaction, Weighting};
use self::core::global;
use self::core::libtx::build::{
	self, initial_tx, input, output, with_excess, with_fee, with_lock_height,
};
use self::core::libtx::ProofBuilder;
use self::core::ser;
use self::keychain::{ExtKeychain, Identifier, Keychain};
use self::util::RwLock;
use crate::common::{new_block, tx1i1o, tx1i2o, tx2i1o};
use crate::util::secp::pedersen::Commitment;
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_util as util;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use std::u32;

#[test]
fn simple_tx_ser() {
	let tx = tx2i1o();
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &tx).expect("serialization failed");
	let target_len = 238;
	assert_eq!(vec.len(), target_len,);

	let tx = tx1i2o();
	println!("tx = {}", serde_json::to_string_pretty(&tx).unwrap());
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &tx).expect("serialization failed");
	let target_len = 257;
	println!("tx vec = {:02x?}", vec);
	assert_eq!(vec.len(), target_len,);
}

#[test]
fn simple_tx_ser_deser() {
	let tx = tx2i1o();
	let mut vec = Vec::new();
	ser::serialize_default(&mut vec, &tx).expect("serialization failed");
	let dtx: Transaction = ser::deserialize_default(&mut &vec[..]).unwrap();
	assert_eq!(dtx.fee(), 2);
	assert_eq!(dtx.inputs().len(), 2);
	assert_eq!(dtx.outputs().len(), 1);
	assert_eq!(tx.hash(), dtx.hash());
}

#[test]
fn tx_double_ser_deser() {
	// checks serializing doesn't mess up the tx and produces consistent results
	let btx = tx2i1o();

	let mut vec = Vec::new();
	assert!(ser::serialize_default(&mut vec, &btx).is_ok());
	let dtx: Transaction = ser::deserialize_default(&mut &vec[..]).unwrap();

	let mut vec2 = Vec::new();
	assert!(ser::serialize_default(&mut vec2, &btx).is_ok());
	let dtx2: Transaction = ser::deserialize_default(&mut &vec2[..]).unwrap();

	assert_eq!(btx.hash(), dtx.hash());
	assert_eq!(dtx.hash(), dtx2.hash());
}

#[test]
fn test_zero_commit_fails() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

	// blinding should fail as signing with a zero r*G shouldn't work
	assert!(build::transaction(
		vec![
			input(10, 0i64, key_id1.clone()),
			output(10, Some(0i64), key_id1.clone()),
		],
		&keychain,
		&builder,
	)
	.is_err());
}

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

#[test]
fn build_tx_fee_overflow() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0);

	let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
	let (pre_tx, _) =
		build::partial_transaction(vec![output(10, Some(0i64), key_id1)], &keychain, &builder)
			.unwrap();
	complete_inputs.insert(
		pre_tx.body.outputs[0].commit,
		OutputEx {
			output: pre_tx.body.outputs[0],
			height: 0,
			mmr_index: 1,
		},
	);

	// first build a valid tx with corresponding blinding factor
	let tx = build::transaction(
		vec![
			input(10, 0i64, key_id1),
			output(5, Some(0i64), key_id2),
			output(6 + 1000_000, Some(0i64), key_id3),
			with_fee(u32::MAX - 1000_000),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	// check the tx is invalid
	assert_eq!(
		tx.validate(
			Weighting::AsTransaction,
			verifier_cache(),
			Some(&complete_inputs),
			1
		),
		Err(core::core::transaction::Error::TransactionSumMismatch)
	);

	// check the kernel is itself valid
	assert_eq!(tx.kernels().len(), 1);
	let kern = &tx.kernels()[0];
	kern.verify().unwrap();

	assert_eq!(
		kern.features,
		KernelFeatures::Plain {
			fee: u32::MAX - 1000_000
		}
	);
	assert_eq!(u32::MAX as u64 - 1000_000, tx.fee());
}

#[test]
fn build_tx_kernel() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0);

	let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
	let (pre_tx, _) =
		build::partial_transaction(vec![output(10, Some(0i64), key_id1)], &keychain, &builder)
			.unwrap();
	complete_inputs.insert(
		pre_tx.body.outputs[0].commit,
		OutputEx {
			output: pre_tx.body.outputs[0],
			height: 0,
			mmr_index: 1,
		},
	);

	// first build a valid tx with corresponding blinding factor
	let tx = build::transaction(
		vec![
			input(10, 0i64, key_id1),
			output(5, Some(0i64), key_id2),
			output(3, Some(0i64), key_id3),
			with_fee(2),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	// check the tx is valid
	tx.validate(
		Weighting::AsTransaction,
		verifier_cache(),
		Some(&complete_inputs),
		1,
	)
	.unwrap();

	// check the kernel is also itself valid
	assert_eq!(tx.kernels().len(), 1);
	let kern = &tx.kernels()[0];
	kern.verify().unwrap();

	assert_eq!(kern.features, KernelFeatures::Plain { fee: 2 });
	assert_eq!(2, tx.fee());
}

// Combine two transactions into one big transaction (with multiple kernels)
// and check it still validates.
#[test]
fn transaction_cut_through() {
	let tx1 = tx1i2o();
	let tx2 = tx2i1o();

	assert!(tx1
		.validate(Weighting::AsTransaction, verifier_cache(), None, 1)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, verifier_cache(), None, 1)
		.is_ok());

	let vc = verifier_cache();

	// now build a "cut_through" tx from tx1 and tx2
	let tx3 = aggregate(vec![tx1, tx2]).unwrap();

	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 1)
		.is_ok());
}

// Attempt to deaggregate a multi-kernel transaction in a different way
#[test]
fn multi_kernel_transaction_deaggregation() {
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();
	let tx4 = tx1i1o();

	let vc = verifier_cache();

	assert!(tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx4
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let tx1234 = aggregate(vec![tx1.clone(), tx2.clone(), tx3.clone(), tx4.clone()]).unwrap();
	let tx12 = aggregate(vec![tx1.clone(), tx2.clone()]).unwrap();
	let tx34 = aggregate(vec![tx3.clone(), tx4.clone()]).unwrap();

	assert!(tx1234
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx12
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx34
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let deaggregated_tx34 = deaggregate(tx1234.clone(), vec![tx12.clone()]).unwrap();
	assert!(deaggregated_tx34
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx34, deaggregated_tx34);

	let deaggregated_tx12 = deaggregate(tx1234.clone(), vec![tx34.clone()]).unwrap();

	assert!(deaggregated_tx12
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx12, deaggregated_tx12);
}

#[test]
fn multi_kernel_transaction_deaggregation_2() {
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();

	let vc = verifier_cache();

	assert!(tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let tx123 = aggregate(vec![tx1.clone(), tx2.clone(), tx3.clone()]).unwrap();
	let tx12 = aggregate(vec![tx1.clone(), tx2.clone()]).unwrap();

	assert!(tx123
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx12
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let deaggregated_tx3 = deaggregate(tx123.clone(), vec![tx12.clone()]).unwrap();
	assert!(deaggregated_tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx3, deaggregated_tx3);
}

#[test]
fn multi_kernel_transaction_deaggregation_3() {
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();

	let vc = verifier_cache();

	assert!(tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let tx123 = aggregate(vec![tx1.clone(), tx2.clone(), tx3.clone()]).unwrap();
	let tx13 = aggregate(vec![tx1.clone(), tx3.clone()]).unwrap();
	let tx2 = aggregate(vec![tx2.clone()]).unwrap();

	assert!(tx123
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let deaggregated_tx13 = deaggregate(tx123.clone(), vec![tx2.clone()]).unwrap();
	assert!(deaggregated_tx13
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx13, deaggregated_tx13);
}

#[test]
fn multi_kernel_transaction_deaggregation_4() {
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();
	let tx4 = tx1i1o();
	let tx5 = tx1i1o();

	let vc = verifier_cache();

	assert!(tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx4
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx5
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let tx12345 = aggregate(vec![
		tx1.clone(),
		tx2.clone(),
		tx3.clone(),
		tx4.clone(),
		tx5.clone(),
	])
	.unwrap();
	assert!(tx12345
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let deaggregated_tx5 = deaggregate(
		tx12345.clone(),
		vec![tx1.clone(), tx2.clone(), tx3.clone(), tx4.clone()],
	)
	.unwrap();
	assert!(deaggregated_tx5
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx5, deaggregated_tx5);
}

#[test]
fn multi_kernel_transaction_deaggregation_5() {
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();
	let tx4 = tx1i1o();
	let tx5 = tx1i1o();

	let vc = verifier_cache();

	assert!(tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx4
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx5
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let tx12345 = aggregate(vec![
		tx1.clone(),
		tx2.clone(),
		tx3.clone(),
		tx4.clone(),
		tx5.clone(),
	])
	.unwrap();
	let tx12 = aggregate(vec![tx1.clone(), tx2.clone()]).unwrap();
	let tx34 = aggregate(vec![tx3.clone(), tx4.clone()]).unwrap();

	assert!(tx12345
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let deaggregated_tx5 = deaggregate(tx12345.clone(), vec![tx12.clone(), tx34.clone()]).unwrap();
	assert!(deaggregated_tx5
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx5, deaggregated_tx5);
}

// Attempt to deaggregate a multi-kernel transaction
#[test]
fn basic_transaction_deaggregation() {
	let tx1 = tx1i2o();
	let tx2 = tx2i1o();

	let vc = verifier_cache();

	assert!(tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert!(tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	// now build a "cut_through" tx from tx1 and tx2
	let tx3 = aggregate(vec![tx1.clone(), tx2.clone()]).unwrap();

	assert!(tx3
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());

	let deaggregated_tx1 = deaggregate(tx3.clone(), vec![tx2.clone()]).unwrap();

	assert!(deaggregated_tx1
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx1, deaggregated_tx1);

	let deaggregated_tx2 = deaggregate(tx3.clone(), vec![tx1.clone()]).unwrap();

	assert!(deaggregated_tx2
		.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.is_ok());
	assert_eq!(tx2, deaggregated_tx2);
}

#[test]
fn hash_output() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0);

	let tx = build::transaction(
		vec![
			input(75, 0i64, key_id1),
			output(42, Some(0i64), key_id2),
			output(32, Some(0i64), key_id3),
			with_fee(1),
		],
		&keychain,
		&builder,
	)
	.unwrap();
	let h = tx.outputs()[0].hash();
	assert_ne!(h, ZERO_HASH);
	let h2 = tx.outputs()[1].hash();
	assert_ne!(h, h2);
}

#[test]
fn blind_tx() {
	let btx = tx2i1o();
	assert!(btx
		.validate(Weighting::AsTransaction, verifier_cache(), None, 0)
		.is_ok());
}

#[test]
fn tx_hash_diff() {
	let btx1 = tx2i1o();
	let btx2 = tx1i1o();

	if btx1.hash() == btx2.hash() {
		panic!("diff txs have same hash")
	}
}

/// Simulate the standard exchange between 2 parties when creating a basic
/// 2 inputs, 2 outputs transaction.
#[test]
fn tx_build_exchange() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0);
	let key_id4 = ExtKeychain::derive_key_id(1, 4, 0, 0, 0);

	let (tx_alice, blind_sum) = {
		// Alice gets 2 of her pre-existing outputs to send 5 coins to Bob, they
		// become inputs in the new transaction
		let (in1, in2) = (input(4, 0i64, key_id1), input(3, 0i64, key_id2));

		// Alice builds her transaction, with change, which also produces the sum
		// of blinding factors before they're obscured.
		let (tx, sum) = build::partial_transaction(
			vec![in1, in2, output(1, Some(0i64), key_id3), with_fee(2)],
			&keychain,
			&builder,
		)
		.unwrap();

		(tx, sum)
	};

	// From now on, Bob only has the obscured transaction and the sum of
	// blinding factors. He adds his output, finalizes the transaction so it's
	// ready for broadcast.
	let tx_final = build::transaction(
		vec![
			initial_tx(tx_alice),
			with_excess(blind_sum),
			output(4, Some(0i64), key_id4),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	tx_final
		.validate(Weighting::AsTransaction, verifier_cache(), None, 0)
		.unwrap();
}

#[test]
fn reward_empty_block() {
	global::set_mining_mode(global::ChainTypes::AutomatedTesting);
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

	let previous_header = BlockHeader::default();

	let b = new_block(vec![], &keychain, &builder, &previous_header, &key_id);

	b.cut_through()
		.unwrap()
		.validate(verifier_cache(), None)
		.unwrap();
}

#[test]
fn reward_with_tx_block() {
	global::set_mining_mode(global::ChainTypes::AutomatedTesting);
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

	let vc = verifier_cache();

	let mut tx1 = tx2i1o();
	tx1.validate(Weighting::AsTransaction, vc.clone(), None, 0)
		.unwrap();

	let previous_header = BlockHeader::default();

	let block = new_block(
		vec![&mut tx1],
		&keychain,
		&builder,
		&previous_header,
		&key_id,
	);
	block
		.cut_through()
		.unwrap()
		.validate(vc.clone(), None)
		.unwrap();
}

#[test]
fn simple_block() {
	global::set_mining_mode(global::ChainTypes::AutomatedTesting);
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

	let vc = verifier_cache();

	let mut tx1 = tx2i1o();
	let mut tx2 = tx1i1o();

	let previous_header = BlockHeader::default();
	let b = new_block(
		vec![&mut tx1, &mut tx2],
		&keychain,
		&builder,
		&previous_header,
		&key_id,
	);

	b.validate(vc.clone(), None).unwrap();
}

#[test]
fn test_block_with_timelocked_tx() {
	global::set_mining_mode(global::ChainTypes::AutomatedTesting);
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0);

	let vc = verifier_cache();

	// first check we can add a timelocked tx where lock height matches current
	// block height and that the resulting block is valid
	let tx1 = build::transaction(
		vec![
			input(5, 0i64, key_id1.clone()),
			output(3, Some(0i64), key_id2.clone()),
			with_fee(2),
			with_lock_height(1),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	let previous_header = BlockHeader::default();

	let b = new_block(
		vec![&tx1],
		&keychain,
		&builder,
		&previous_header,
		&key_id3.clone(),
	);
	b.validate(vc.clone(), None).unwrap();

	// now try adding a timelocked tx where lock height is greater than current
	// block height
	let tx1 = build::transaction(
		vec![
			input(5, 0i64, key_id1.clone()),
			output(3, Some(0i64), key_id2.clone()),
			with_fee(2),
			with_lock_height(2),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	let previous_header = BlockHeader::default();
	let b = new_block(
		vec![&tx1],
		&keychain,
		&builder,
		&previous_header,
		&key_id3.clone(),
	);

	match b.validate(vc.clone(), None) {
		Err(KernelLockHeight(height)) => {
			assert_eq!(height, 2);
		}
		_ => panic!("expecting KernelLockHeight error here"),
	}
}

#[test]
pub fn test_verify_1i1o_sig() {
	let tx = tx1i1o();
	tx.validate(Weighting::AsTransaction, verifier_cache(), None, 0)
		.unwrap();
}

#[test]
pub fn test_verify_2i1o_sig() {
	let tx = tx2i1o();
	tx.validate(Weighting::AsTransaction, verifier_cache(), None, 0)
		.unwrap();
}
