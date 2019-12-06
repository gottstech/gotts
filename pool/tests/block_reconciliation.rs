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

use self::core::core::hash::Hashed;
use self::core::core::verifier_cache::LruVerifierCache;
use self::core::core::{Block, BlockHeader};
use self::core::libtx;
use self::core::pow::Difficulty;
use self::keychain::{ExtKeychain, Identifier, Keychain};
use self::util::RwLock;
use crate::common::ChainAdapter;
use crate::common::*;
use gotts_core as core;
use gotts_keychain as keychain;
use gotts_util as util;
use std::sync::Arc;

#[test]
fn test_transaction_pool_block_reconciliation() {
	let keychain: ExtKeychain = Keychain::from_random_seed(false).unwrap();

	let db_root = ".gotts_block_reconciliation".to_string();
	clean_output_dir(db_root.clone());
	{
		let chain = Arc::new(ChainAdapter::init(db_root.clone()).unwrap());

		let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));

		// Initialize a new pool with our chain adapter.
		let pool = RwLock::new(test_setup(chain.clone(), verifier_cache.clone()));

		let header = {
			let height = 1;
			let key_id = ExtKeychain::derive_key_id(1, height as u32, 0, 0, 0);
			let reward = libtx::reward::output(
				&keychain,
				&libtx::ProofBuilder::new(&keychain, &Identifier::zero()),
				&key_id,
				0,
				false,
			)
			.unwrap();
			let genesis = BlockHeader::default();
			let mut block = Block::new(&genesis, vec![], Difficulty::min(), reward).unwrap();

			// Set the prev_root to the prev hash for testing purposes (no MMR to obtain a root from).
			block.header.prev_root = genesis.hash();

			chain.update_db_for_block(&block);

			block.header
		};

		// Now create tx to spend that first coinbase (now matured).
		// Provides us with some useful outputs to test with.
		let initial_tx =
			test_transaction_spending_coinbase(&keychain, &header, vec![1000, 2000, 3000, 4000]);

		let block = {
			let key_id = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
			let fees = initial_tx.fee();
			let reward = libtx::reward::output(
				&keychain,
				&libtx::ProofBuilder::new(&keychain, &Identifier::zero()),
				&key_id,
				fees,
				false,
			)
			.unwrap();
			let mut block =
				Block::new(&header, vec![initial_tx], Difficulty::min(), reward).unwrap();

			// Set the prev_root to the prev hash for testing purposes (no MMR to obtain a root from).
			block.header.prev_root = header.hash();

			chain.update_db_for_block(&block);

			block
		};

		let header = block.header;

		// Preparation: We will introduce three root pool transactions.
		// 1. A transaction that should be invalidated because it is exactly
		//  contained in the block.
		// 2. A transaction that should be invalidated because the input is
		//  consumed in the block, although it is not exactly consumed.
		// 3. A transaction that should remain after block reconciliation.
		let block_transaction = test_transaction(&keychain, vec![1000], vec![800]);
		let conflict_transaction = test_transaction(&keychain, vec![2000], vec![1200, 600]);
		let valid_transaction = test_transaction(&keychain, vec![3000], vec![1300, 1500]);

		// We will also introduce a few children:
		// 4. A transaction that descends from transaction 1, that is in
		//  turn exactly contained in the block.
		let block_child = test_transaction(&keychain, vec![800], vec![500, 100]);
		// 5. A transaction that descends from transaction 4, that is not
		//  contained in the block at all and should be valid after
		//  reconciliation.
		let pool_child = test_transaction(&keychain, vec![500], vec![300]);
		// 6. A transaction that descends from transaction 2 that does not
		//  conflict with anything in the block in any way, but should be
		//  invalidated (orphaned).
		let conflict_child = test_transaction(&keychain, vec![1200], vec![200]);
		// 7. A transaction that descends from transaction 2 that should be
		//  valid due to its inputs being satisfied by the block.
		let conflict_valid_child = test_transaction(&keychain, vec![600], vec![400]);
		// 8. A transaction that descends from transaction 3 that should be
		//  invalidated due to an output conflict.
		let valid_child_conflict = test_transaction(&keychain, vec![1300], vec![900]);
		// 9. A transaction that descends from transaction 3 that should remain
		//  valid after reconciliation.
		let valid_child_valid = test_transaction(&keychain, vec![1500], vec![1100]);
		// 10. A transaction that descends from both transaction 6 and
		//  transaction 9
		let mixed_child = test_transaction(&keychain, vec![200, 1100], vec![700]);

		let txs_to_add = vec![
			block_transaction,
			conflict_transaction,
			valid_transaction.clone(),
			block_child,
			pool_child.clone(),
			conflict_child,
			conflict_valid_child.clone(),
			valid_child_conflict.clone(),
			valid_child_valid.clone(),
			mixed_child,
		];

		// First we add the above transactions to the pool.
		// All should be accepted.
		{
			let mut write_pool = pool.write();
			assert_eq!(write_pool.total_size(), 0);

			for tx in &txs_to_add {
				write_pool
					.add_to_pool(test_source(), tx.clone(), false, &header)
					.unwrap();
			}

			assert_eq!(write_pool.total_size(), txs_to_add.len());
		}

		// Now we prepare the block that will cause the above conditions to be met.
		// First, the transactions we want in the block:
		// - Copy of 1
		let block_tx_1 = test_transaction(&keychain, vec![1000], vec![800]);
		// - Conflict w/ 2, satisfies 7
		let block_tx_2 = test_transaction(&keychain, vec![2000], vec![600]);
		// - Copy of 4
		let block_tx_3 = test_transaction(&keychain, vec![800], vec![500, 100]);
		// - Output conflict w/ 8
		let block_tx_4 = test_transaction(&keychain, vec![4000], vec![900, 3100]);

		let block_txs = vec![block_tx_1, block_tx_2, block_tx_3, block_tx_4];

		// Now apply this block.
		let block = {
			let key_id = ExtKeychain::derive_key_id(1, 3, 0, 0, 0);
			let fees = block_txs.iter().map(|tx| tx.fee()).sum();
			let reward = libtx::reward::output(
				&keychain,
				&libtx::ProofBuilder::new(&keychain, &Identifier::zero()),
				&key_id,
				fees,
				false,
			)
			.unwrap();
			let mut block = Block::new(&header, block_txs, Difficulty::min(), reward).unwrap();

			// Set the prev_root to the prev hash for testing purposes (no MMR to obtain a root from).
			block.header.prev_root = header.hash();

			chain.update_db_for_block(&block);
			block
		};

		// Check the pool still contains everything we expect at this point.
		{
			let write_pool = pool.write();
			assert_eq!(write_pool.total_size(), txs_to_add.len());
		}

		// And reconcile the pool with this latest block.
		{
			let mut write_pool = pool.write();
			write_pool.reconcile_block(&block).unwrap();

			assert_eq!(write_pool.total_size(), 4);
			assert_eq!(write_pool.txpool.entries[0].tx, valid_transaction);
			assert_eq!(write_pool.txpool.entries[1].tx, pool_child);
			assert_eq!(write_pool.txpool.entries[2].tx, conflict_valid_child);
			assert_eq!(write_pool.txpool.entries[3].tx, valid_child_valid);
		}
	}
	// Cleanup db directory
	clean_output_dir(db_root.clone());
}
