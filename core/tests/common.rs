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

//! Common test functions

use chrono::{DateTime, Duration, Utc};
use gotts_core::core::price;
use gotts_core::core::price::{get_median_price, prices_root, ExchangeRates, PriceVersion};
use gotts_core::core::{
	block::{Block, BlockHeader},
	Transaction,
};
use gotts_core::libtx::{
	build::{self, input, output, with_fee},
	proof::{ProofBuild, ProofBuilder},
	reward,
};
use gotts_core::pow::Difficulty;
use gotts_keychain as keychain;
use gotts_keychain::{Identifier, Keychain};
use gotts_util::secp;
use gotts_util::secp::key::PublicKey;
use gotts_util::secp::Signature;

// utility producing a transaction with 2 inputs and a single outputs
pub fn tx2i1o() -> Transaction {
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = keychain::ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = keychain::ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = keychain::ExtKeychain::derive_key_id(1, 3, 0, 0, 0);

	build::transaction(
		vec![
			input(10, 0i64, key_id1),
			input(11, 0i64, key_id2),
			output(19, Some(0i64), key_id3),
			with_fee(2),
		],
		&keychain,
		&builder,
	)
	.unwrap()
}

// utility producing a transaction with a single input and output
pub fn tx1i1o() -> Transaction {
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = keychain::ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = keychain::ExtKeychain::derive_key_id(1, 2, 0, 0, 0);

	build::transaction(
		vec![
			input(5, 0i64, key_id1),
			output(3, Some(0i64), key_id2),
			with_fee(2),
		],
		&keychain,
		&builder,
	)
	.unwrap()
}

// utility producing a transaction with a single input
// and two outputs (one change output)
// Note: this tx has an "offset" kernel
pub fn tx1i2o() -> Transaction {
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let key_id1 = keychain::ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let key_id2 = keychain::ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
	let key_id3 = keychain::ExtKeychain::derive_key_id(1, 3, 0, 0, 0);

	build::transaction(
		vec![
			input(6, 0i64, key_id1),
			output(3, Some(0i64), key_id2),
			output(1, Some(0i64), key_id3),
			with_fee(2),
		],
		&keychain,
		&builder,
	)
	.unwrap()
}

/// Generate a test price for a block.
pub fn generate_prices_for_block(b: &mut Block) {
	b.prices = generate_test_prices(b.header.timestamp);
	b.header.median_price = get_median_price(&b.prices).unwrap();
	let (price_root, price_mmr_size) = prices_root(&b.prices).unwrap();
	b.header.price_root = price_root;
	b.header.price_mmr_size = price_mmr_size;
}

/// Generate a test price.
fn generate_test_prices(header_timestamp: DateTime<Utc>) -> Vec<ExchangeRates> {
	let mut prices: Vec<ExchangeRates> = vec![];
	let keychain = price::auto_test_feeder_keychain();

	let key_id_0 = keychain::ExtKeychain::derive_key_id(3, 1, 0, 0, 0);
	let prikey_0 = keychain.derive_key(&key_id_0).unwrap();
	let pubkey_0 = PublicKey::from_secret_key(keychain.secp(), &prikey_0).unwrap();

	let mut price = ExchangeRates {
		version: PriceVersion(0),
		source_uid: 0,
		pairs: vec![
			7944.59_f64,
			138.95_f64,
			1.1116_f64,
			1.3111_f64,
			6.9481_f64,
			109.22_f64,
			1.3037_f64,
		],
		date: header_timestamp - Duration::seconds(1),
		sig: Signature::from(secp::ffi::Signature::new()),
	};

	let secp = keychain.secp();
	price.sig = secp::aggsig::sign_single(
		&secp,
		&price.price_sig_msg().unwrap(),
		&prikey_0,
		None,
		None,
		None,
		Some(&pubkey_0),
		None,
	)
	.unwrap();
	prices.push(price.clone());

	prices
}

// utility to create a block without worrying about the key or previous
// header
pub fn new_block<K, B>(
	txs: Vec<&Transaction>,
	keychain: &K,
	builder: &B,
	previous_header: &BlockHeader,
	key_id: &Identifier,
) -> Block
where
	K: Keychain,
	B: ProofBuild,
{
	let fees = txs.iter().map(|tx| tx.fee()).sum();
	let reward_output = reward::output(keychain, builder, &key_id, fees, false).unwrap();
	let mut b = Block::new(
		&previous_header,
		txs.into_iter().cloned().collect(),
		Difficulty::min(),
		reward_output,
	)
	.unwrap();
	generate_prices_for_block(&mut b);
	b
}

// utility producing a transaction that spends an output with the provided
// value and blinding key
pub fn txspend1i1o<K, B>(
	v: u64,
	keychain: &K,
	builder: &B,
	key_id1: Identifier,
	key_id2: Identifier,
) -> Transaction
where
	K: Keychain,
	B: ProofBuild,
{
	build::transaction(
		vec![
			input(v, 0i64, key_id1),
			output(3, Some(0i64), key_id2),
			with_fee(2),
		],
		keychain,
		builder,
	)
	.unwrap()
}
