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

//! Definition of the genesis block. Placeholder for now.

// required for genesis replacement
//! #![allow(unused_imports)]

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]

use chrono::prelude::{TimeZone, Utc};

use crate::consensus;
use crate::core;
use crate::libtx::proof::SecuredPath;
use crate::pow::{Difficulty, Proof, ProofOfWork};
use crate::util;
use crate::util::secp::pedersen::Commitment;
use crate::util::secp::Signature;

use crate::core::hash::Hash;

/// Genesis block definition for development networks. The proof of work size
/// is small enough to mine it on the fly, so it does not contain its own
/// proof of work solution. Can also be easily mutated for different tests.
pub fn genesis_dev() -> core::Block {
	core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(1997, 8, 4).and_hms(0, 0, 0),
		pow: ProofOfWork {
			nonce: 0,
			..Default::default()
		},
		..Default::default()
	})
}

/// Floonet genesis block
pub fn genesis_floo() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2019, 12, 6).and_hms(10, 10, 37),
		prev_root: Hash::from_hex(
			"00000000000000000001d9e109f3d6803d7fd5d2140c7ee75258289cc0a8c9dd",
		)
		.unwrap(),
		output_i_root: Hash::from_hex(
			"6a996c4bc4498869720a2011f0f5e4e1448c5f69c4e536746019dc198cc99c86",
		)
		.unwrap(),
		output_ii_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"a7a1066efbdb7c11b308c19c061a5dd3aff71f52a9a5d0b18c89584e1e6fcf74",
		)
		.unwrap(),
		output_i_mmr_size: 1,
		output_ii_mmr_size: 0,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(3)),
			secondary_scaling: 1856,
			nonce: 7,
			proof: Proof {
				nonces: vec![
					3693091, 6647809, 8167299, 18449581, 29988755, 76085502, 98400296, 107591918,
					130175155, 150750946, 153604229, 171111155, 202813214, 210108053, 260775114,
					282146891, 289372347, 291460826, 295067268, 296005855, 306472220, 307181476,
					328933928, 361202447, 371668337, 408860544, 420398904, 421354254, 423031020,
					426206487, 433328203, 437600629, 438818352, 444188167, 445824717, 447764188,
					479576377, 484019713, 498562620, 508206041, 521593429, 524134681,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(util::from_hex("098364706891b414a55a91ef8686c51ec70d4b779052977009f625630e17a2f1c3".to_string()).unwrap()),
		excess_sig: Signature::from_compact(&util::from_hex("aa2ebd4aa20557cd620d75d996683eecde521d77e72d7725fbbd85f141e7ce6b7c9c6f09fb2a4d94a38ddf444ff4ea6815ebf21ede63ad7a7f4d3fd8124eef77".to_string()).unwrap()).unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeaturesEx::Coinbase {
			spath: SecuredPath::from_vec(
				util::from_hex("bd3be4bdd2a8d4a7a8559bbf".to_string()).unwrap(),
			),
		},
		commit: Commitment::from_vec(
			util::from_hex(
				"098364706891b414a55a91ef8686c51ec70d4b779052977009f625630e17a2f1c3".to_string(),
			)
			.unwrap(),
		),
		value: consensus::REWARD,
	};
	gen.with_reward(output, kernel)
}

/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2020, 1, 15).and_hms(12, 0, 0), // REPLACE
		prev_root: Hash::default(),                        // REPLACE
		output_i_root: Hash::default(),                    // REPLACE
		output_ii_root: Hash::default(),                   // REPLACE
		kernel_root: Hash::default(),                      // REPLACE
		output_i_mmr_size: 1,
		output_ii_mmr_size: 0,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(8)),
			secondary_scaling: 1856,
			nonce: 1, // REPLACE
			proof: Proof {
				nonces: vec![0; 42], // REPLACE
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(vec![]), // REPLACE
		excess_sig: Signature::from_raw_data(&[0; 64]).unwrap(), //REPLACE
	};
	let output = core::Output {
		features: core::OutputFeaturesEx::Coinbase {
			spath: SecuredPath::from_vec(vec![]), // REPLACE
		},
		commit: Commitment::from_vec(vec![]), // REPLACE
		value: consensus::REWARD,
	};
	gen.with_reward(output, kernel)
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hashed;
	use crate::ser::{self, ProtocolVersion};

	#[test]
	fn floonet_genesis_hash() {
		let gen_hash = genesis_floo().hash();
		println!("floonet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_floo(), ProtocolVersion(1)).unwrap();
		println!("floonet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"1ecf38f5cf17a2734d4bc26251ba990487e360103b46741c49acb685b8e41075"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"1ca3d80c48f409e0cc9de0d8382cb958f0b761ea9f5047e80906f48c50b73553"
		);
	}

	#[test]
	fn mainnet_genesis_hash() {
		let gen_hash = genesis_main().hash();
		println!("mainnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_main(), ProtocolVersion(1)).unwrap();
		println!("mainnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"cd27d5a8dabd8001a3035890832efd948544aaa8a0599a9ad618300106fd7805"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"0a6d78ac2ef38ba9373a62e3dd1acde7236bd94d8d370af58755683245a0ad43"
		);
	}
}
