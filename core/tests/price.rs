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
use crate::common::{new_block, tx1i2o};
use crate::core::core::block;
use crate::core::core::price;
use crate::core::core::price::{
	decode_price, get_median_price, prices_root, ExchangeRates, PriceVersion,
};
use crate::core::core::verifier_cache::{LruVerifierCache, VerifierCache};
use crate::core::core::BlockHeader;
use crate::core::global;
use crate::core::libtx::ProofBuilder;
use crate::keychain::{ExtKeychain, Identifier, Keychain};
use crate::util::secp;
use crate::util::secp::key::PublicKey;
use crate::util::secp::Signature;
use crate::util::RwLock;
use chrono::{DateTime, Duration, Utc};
use gotts_core as core;
use gotts_core::global::ChainTypes;
use gotts_keychain as keychain;
use gotts_util as util;
use std::sync::Arc;

fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
	Arc::new(RwLock::new(LruVerifierCache::new()))
}

fn generate_a_price(timestamp: DateTime<Utc>, source_uid: u16, price_bias: f64) -> ExchangeRates {
	let keychain = price::auto_test_feeder_keychain();

	let key_id = keychain::ExtKeychain::derive_key_id(3, 1, 0, source_uid as u32, 0);
	let prikey = keychain.derive_key(&key_id).unwrap();
	let pubkey = PublicKey::from_secret_key(keychain.secp(), &prikey).unwrap();
	let mut price = ExchangeRates {
		version: PriceVersion(0),
		source_uid,
		pairs: vec![
			7944.59_f64,
			138.95_f64,
			1.1116_f64,
			1.3111_f64,
			6.9481_f64,
			109.22_f64,
			1.3037_f64,
		],
		date: timestamp,
		sig: Signature::from(secp::ffi::Signature::new()),
	};
	for i in 0..price.pairs.len() {
		price.pairs[i] += price_bias;
	}

	let secp = keychain.secp();
	price.sig = secp::aggsig::sign_single(
		&secp,
		&price.price_sig_msg().unwrap(),
		&prikey,
		None,
		None,
		None,
		Some(&pubkey),
		None,
	)
	.unwrap();

	price
}

#[test]
fn prices_in_block() {
	util::init_test_logger();
	global::set_mining_mode(ChainTypes::AutomatedTesting);
	let tx1 = tx1i2o();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain, &Identifier::zero());
	let prev = BlockHeader::default();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let mut b = new_block(vec![&tx1], &keychain, &builder, &prev, &key_id);
	let header_timestamp = b.header.timestamp;

	let mut prices: Vec<ExchangeRates> = vec![];
	prices.push(generate_a_price(
		header_timestamp - Duration::seconds(1),
		0,
		0f64,
	));
	// one more price with 0.01 increment
	prices.push(generate_a_price(
		header_timestamp - Duration::seconds(2),
		1,
		0.01f64,
	));
	// one more price with 0.01 decrement
	prices.push(generate_a_price(
		header_timestamp - Duration::seconds(3),
		2,
		-0.01f64,
	));

	prices.sort_unstable();
	b.prices = prices.clone();
	b.header.median_price = get_median_price(&b.prices).unwrap();
	let (price_root, price_mmr_size) = prices_root(&b.prices).unwrap();
	b.header.price_root = price_root;
	b.header.price_mmr_size = price_mmr_size;

	// check whether the median price is correct
	assert_eq!(
		decode_price(&b.header.median_price.prices),
		vec![
			7944.59_f64,
			138.95_f64,
			1.1116_f64,
			1.3111_f64,
			6.9481_f64,
			109.22_f64,
			1.3037_f64,
		]
	);

	b.validate(verifier_cache(), None).unwrap();

	// check one more price with same source uid will fail on validation
	prices.push(generate_a_price(
		header_timestamp - Duration::seconds(4),
		2,
		0.02f64,
	));
	prices.sort_unstable();
	b.prices = prices;
	b.header.median_price = get_median_price(&b.prices).unwrap();
	let (price_root, price_mmr_size) = prices_root(&b.prices).unwrap();
	b.header.price_root = price_root;
	b.header.price_mmr_size = price_mmr_size;
	assert_eq!(
		b.validate(verifier_cache(), None),
		Err(block::Error::PriceDuplicatedSource),
	);
}
