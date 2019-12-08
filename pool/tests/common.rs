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

use self::chain::store::ChainStore;
use self::chain::types::Tip;
use self::core::core::hash::{Hash, Hashed};
use self::core::core::verifier_cache::VerifierCache;
use self::core::core::{Block, BlockHeader, BlockSums, Committed, Input, OutputEx, Transaction};
use self::core::libtx;
use self::keychain::{ExtKeychain, Identifier, Keychain};
use self::pool::types::*;
use self::pool::TransactionPool;
use self::util::secp::pedersen::Commitment;
use self::util::RwLock;
use gotts_chain as chain;
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_pool as pool;
use gotts_util as util;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

#[derive(Clone)]
pub struct ChainAdapter {
	pub store: Arc<RwLock<ChainStore>>,
	pub utxo: Arc<RwLock<HashMap<Commitment, OutputEx>>>,
}

impl ChainAdapter {
	pub fn init(db_root: String) -> Result<ChainAdapter, String> {
		let target_dir = format!("target/{}", db_root);
		let chain_store = ChainStore::new(&target_dir)
			.map_err(|e| format!("failed to init chain_store, {:?}", e))?;
		let store = Arc::new(RwLock::new(chain_store));
		let utxo = Arc::new(RwLock::new(HashMap::new()));

		Ok(ChainAdapter { store, utxo })
	}

	pub fn update_db_for_block(&self, block: &Block) {
		let header = &block.header;
		let tip = Tip::from_header(header);
		let s = self.store.write();
		let batch = s.batch().unwrap();

		batch.save_block_header(header).unwrap();
		batch.save_body_head(&tip).unwrap();
		batch.save_header_head(&tip).unwrap();

		// Retrieve previous block_sums from the db.
		let prev_sums = if let Ok(prev_sums) = batch.get_block_sums(&tip.prev_block_h) {
			prev_sums
		} else {
			BlockSums::default()
		};

		// Overage is based purely on the new block.
		// Previous block_sums have taken all previous overage into account.
		let _overage = header.overage();

		// Verify the kernel sums for the block_sums with the new block applied.
		let (utxo_sum, kernel_sum) = (prev_sums, block as &dyn Committed)
			.verify_kernel_sums()
			.unwrap();

		let block_sums = BlockSums {
			utxo_sum,
			kernel_sum,
		};
		batch.save_block_sums(&header.hash(), &block_sums).unwrap();

		batch.commit().unwrap();

		{
			let mut utxo = self.utxo.write();
			for x in block.inputs() {
				utxo.remove(&x.commitment());
			}
			for x in block.outputs() {
				utxo.insert(
					x.commitment(),
					OutputEx {
						output: x.clone(),
						height: header.height,
						mmr_index: 0, // not used here
					},
				);
			}
		}
	}
}

impl BlockChain for ChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		let s = self.store.read();
		s.head_header()
			.map_err(|_| PoolError::Other(format!("failed to get chain head")))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, PoolError> {
		let s = self.store.read();
		s.get_block_header(hash)
			.map_err(|_| PoolError::Other(format!("failed to get block header")))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, PoolError> {
		let s = self.store.read();
		s.get_block_sums(hash)
			.map_err(|_| PoolError::Other(format!("failed to get block sums")))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), pool::PoolError> {
		let utxo = self.utxo.read();
		let mut total_inputs_value = 0u64;
		let mut total_outputs_value = 0u64;

		for x in tx.outputs() {
			if utxo.contains_key(&x.commitment()) {
				return Err(PoolError::Other(format!("output commitment not unique")));
			}
			total_outputs_value = total_outputs_value.saturating_add(x.value);
		}

		for x in tx.inputs() {
			if !utxo.contains_key(&x.commitment()) {
				return Err(PoolError::Other(format!("not in utxo set")));
			}
			total_inputs_value =
				total_inputs_value.saturating_add(utxo.get(&x.commitment()).unwrap().output.value);
		}
		if total_inputs_value != total_outputs_value.saturating_add(tx.overage()) {
			println!(
				"tx {} sum validate fail. total inputs: {}, total outputs: {}, fee: {}",
				tx.hash(),
				total_inputs_value,
				total_outputs_value,
				tx.overage(),
			);
			return Err(PoolError::Other(format!("transaction sum mismatch")))?;
		}

		Ok(())
	}

	fn get_complete_inputs(
		&self,
		inputs: &Vec<Input>,
	) -> Result<HashMap<Commitment, OutputEx>, pool::PoolError> {
		let utxo = self.utxo.read();
		let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
		for input in inputs {
			if utxo.contains_key(&input.commitment()) {
				let output_ex = utxo.get(&input.commitment()).unwrap();
				complete_inputs.insert(
					input.commitment().clone(),
					OutputEx {
						output: output_ex.output.clone(),
						height: output_ex.height,
						mmr_index: output_ex.mmr_index,
					},
				);
			}
		}
		Ok(complete_inputs)
	}

	// Mocking this check out for these tests.
	// We will test the Merkle proof verification logic elsewhere.
	fn verify_coinbase_maturity(&self, _tx: &Transaction) -> Result<(), PoolError> {
		Ok(())
	}

	// Mocking this out for these tests.
	fn verify_tx_lock_height(&self, _tx: &Transaction) -> Result<(), PoolError> {
		Ok(())
	}
}

pub fn test_setup(
	chain: Arc<dyn BlockChain>,
	verifier_cache: Arc<RwLock<dyn VerifierCache>>,
) -> TransactionPool {
	TransactionPool::new(
		PoolConfig {
			accept_fee_base: 0,
			max_pool_size: 50,
			max_stempool_size: 50,
			mineable_max_weight: 10_000,
		},
		chain.clone(),
		verifier_cache.clone(),
		Arc::new(NoopAdapter {}),
	)
}

pub fn test_transaction_spending_coinbase<K>(
	keychain: &K,
	header: &BlockHeader,
	output_values: Vec<u64>,
) -> Transaction
where
	K: Keychain,
{
	let output_sum = output_values.iter().sum::<u64>();

	let coinbase_reward: u64 = 60_000_000_000;

	let fees = coinbase_reward - output_sum;

	let mut tx_elements = Vec::new();

	// single input spending a single coinbase (deterministic key_id aka height)
	{
		let key_id = ExtKeychain::derive_key_id(1, header.height as u32, 0, 0, 0);
		tx_elements.push(libtx::build::coinbase_input(coinbase_reward, key_id));
	}

	for output_value in output_values {
		let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0);
		tx_elements.push(libtx::build::output(output_value, Some(0i64), key_id));
	}

	tx_elements.push(libtx::build::with_fee(fees as u32));

	libtx::build::transaction(
		tx_elements,
		keychain,
		&libtx::ProofBuilder::new(keychain, &Identifier::zero()),
	)
	.unwrap()
}

pub fn test_transaction<K>(
	keychain: &K,
	input_values: Vec<u64>,
	output_values: Vec<u64>,
) -> Transaction
where
	K: Keychain,
{
	let input_sum = input_values.iter().sum::<u64>();
	let output_sum = output_values.iter().sum::<u64>();

	let fees = input_sum - output_sum;

	let mut tx_elements = Vec::new();

	for input_value in input_values {
		let key_id = ExtKeychain::derive_key_id(1, input_value as u32, 0, 0, 0);
		tx_elements.push(libtx::build::input(input_value, 0i64, key_id));
	}

	for output_value in output_values {
		let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0);
		tx_elements.push(libtx::build::output(output_value, Some(0i64), key_id));
	}
	tx_elements.push(libtx::build::with_fee(fees as u32));

	libtx::build::transaction(
		tx_elements,
		keychain,
		&libtx::ProofBuilder::new(keychain, &Identifier::zero()),
	)
	.unwrap()
}

pub fn test_bad_transaction<K>(
	keychain: &K,
	input_values: Vec<u64>,
	output_values: Vec<u64>,
) -> Transaction
where
	K: Keychain,
{
	let input_sum = input_values.iter().sum::<u64>();
	let output_sum = output_values.iter().sum::<u64>();

	let fees = input_sum - output_sum;

	let mut tx_elements = Vec::new();

	for input_value in input_values {
		let key_id = ExtKeychain::derive_key_id(1, input_value as u32, 0, 0, 0);
		tx_elements.push(libtx::build::input(input_value, 0i64, key_id));
	}

	for output_value in output_values {
		let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0);
		// output_value + 1 here is a bad output value which has an inflation!
		tx_elements.push(libtx::build::output(output_value + 1, Some(0i64), key_id));
	}
	tx_elements.push(libtx::build::with_fee(fees as u32));

	libtx::build::transaction(
		tx_elements,
		keychain,
		&libtx::ProofBuilder::new(keychain, &Identifier::zero()),
	)
	.unwrap()
}

pub fn test_source() -> TxSource {
	TxSource::Broadcast
}

pub fn clean_output_dir(db_root: String) {
	if let Err(e) = fs::remove_dir_all(format!("target/{}", db_root)) {
		println!("cleaning output dir failed - {:?}", e)
	}
}
