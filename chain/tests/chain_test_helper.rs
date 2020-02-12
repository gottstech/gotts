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

use self::chain::types::NoopAdapter;
use self::chain::types::Options;
use self::chain::Chain;
use self::core::core::hash::Hashed;
use self::core::core::price;
use self::core::core::price::{get_median_price, prices_root, ExchangeRates, PriceVersion};
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::Block;
use self::core::genesis;
use self::core::global::ChainTypes;
use self::core::libtx::{self, reward};
use self::core::{consensus, global, pow};
use self::keychain::{ExtKeychainPath, Identifier, Keychain};
use self::util::secp;
use self::util::secp::key::PublicKey;
use self::util::secp::Signature;
use self::util::RwLock;
use chrono::{DateTime, Duration, Utc};
use gotts_chain as chain;
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_util as util;
use std::fs;
use std::sync::Arc;

pub fn clean_output_dir(dir_name: &str) {
	let _ = fs::remove_dir_all(dir_name);
}

pub fn init_chain(dir_name: &str, genesis: Block) -> Chain {
	let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
	Chain::init(
		dir_name.to_string(),
		Arc::new(NoopAdapter {}),
		genesis,
		pow::verify_size,
		verifier_cache,
		false,
		true,
	)
	.unwrap()
}

/// Build genesis block with reward (non-empty, like we have in mainnet).
fn genesis_block<K>(keychain: &K) -> Block
where
	K: Keychain,
{
	let key_id = keychain::ExtKeychain::derive_key_id(0, 1, 0, 0, 0);
	let reward = reward::output(
		keychain,
		&libtx::ProofBuilder::new(keychain, &Identifier::zero()),
		&key_id,
		0,
		false,
	)
	.unwrap();

	genesis::genesis_dev().with_reward(reward.0, reward.1)
}

/// Generate test prices for a block.
pub fn generate_prices_for_block(b: &mut Block) {
	let mut prices: Vec<ExchangeRates> = vec![];
	prices.push(generate_a_price(
		b.header.timestamp - Duration::seconds(1),
		0,
		0f64,
	));
	prices.push(generate_a_price(
		b.header.timestamp - Duration::seconds(2),
		1,
		0.01f64,
	));

	prices.sort_unstable();
	b.prices = prices;
	b.header.median_price = get_median_price(&b.prices).unwrap();
	let (price_root, price_mmr_size) = prices_root(&b.prices).unwrap();
	b.header.price_root = price_root;
	b.header.price_mmr_size = price_mmr_size;
}

/// Generate a test price.
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

/// Mine a chain of specified length to assist with automated tests.
/// Probably a good idea to call clean_output_dir at the beginning and end of each test.
pub fn mine_chain(dir_name: &str, chain_length: u64) -> Chain {
	global::set_mining_mode(ChainTypes::AutomatedTesting);
	let keychain = keychain::ExtKeychain::from_random_seed(false).unwrap();
	let genesis = genesis_block(&keychain);
	let mut chain = init_chain(dir_name, genesis.clone());

	mine_some_on_top(&mut chain, chain_length, &keychain);
	chain
}

fn mine_some_on_top<K>(chain: &mut Chain, chain_length: u64, keychain: &K)
where
	K: Keychain,
{
	for n in 1..chain_length {
		let prev = chain.head_header().unwrap();
		let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());
		let pk = ExtKeychainPath::new(1, n as u32, 0, 0, 0).to_identifier();
		let reward = libtx::reward::output(
			keychain,
			&libtx::ProofBuilder::new(keychain, &Identifier::zero()),
			&pk,
			0,
			false,
		)
		.unwrap();
		let mut b =
			core::core::Block::new(&prev, vec![], next_header_info.clone().difficulty, reward)
				.unwrap();
		b.header.timestamp = prev.timestamp + Duration::seconds(60);
		b.header.pow.secondary_scaling = next_header_info.secondary_scaling;
		generate_prices_for_block(&mut b);

		chain.set_txhashset_roots(&mut b).unwrap();

		let edge_bits = if n == 2 {
			global::min_edge_bits() + 1
		} else {
			global::min_edge_bits()
		};
		b.header.pow.proof.edge_bits = edge_bits;
		pow::pow_size(
			&mut b.header,
			next_header_info.difficulty,
			global::proofsize(),
			edge_bits,
		)
		.unwrap();
		b.header.pow.proof.edge_bits = edge_bits;

		let bhash = b.hash();
		chain.process_block(b, Options::MINE).unwrap();

		// checking our new head
		let head = chain.head().unwrap();
		assert_eq!(head.height, n);
		assert_eq!(head.last_block_h, bhash);

		// now check the block_header of the head
		let header = chain.head_header().unwrap();
		assert_eq!(header.height, n);
		assert_eq!(header.hash(), bhash);

		// now check the block itself
		let block = chain.get_block(&header.hash()).unwrap();
		assert_eq!(block.header.height, n);
		assert_eq!(block.hash(), bhash);
		assert_eq!(block.outputs().len(), 1);

		// now check the block height index
		let header_by_height = chain.get_header_by_height(n).unwrap();
		assert_eq!(header_by_height.hash(), bhash);

		chain.validate(false).unwrap();
	}
}
