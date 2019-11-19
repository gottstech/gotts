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
		timestamp: Utc.ymd(2019, 11, 19).and_hms(11, 5, 57),
		prev_root: Hash::from_hex(
			"000000000000000000144fd714bfd4ce8d1d4c144e2b16f6159a9917b1570732",
		)
		.unwrap(),
		output_i_root: Hash::from_hex(
			"8233a3826ac81c5077b01e558aef183ff23e7f4df378276b3f1eeef31b9456b6",
		)
		.unwrap(),
		output_ii_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"fda7320458bec205a2d79de0587d0d8b6c7fdcfa1ebb44128e937662a0d26480",
		)
		.unwrap(),
		output_i_mmr_size: 1,
		output_ii_mmr_size: 0,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(3)),
			secondary_scaling: 1856,
			nonce: 10,
			proof: Proof {
				nonces: vec![
					10041868, 10081004, 27450470, 30164461, 31309253, 52957945, 75520034,
					149472619, 155698073, 165023110, 169406003, 201178374, 202536961, 206955939,
					207173826, 207796956, 222586000, 224836028, 236552375, 250069741, 260260498,
					282179934, 286454758, 303922880, 314959757, 323525307, 331775582, 338127072,
					347103743, 348610726, 386218307, 409319759, 441701070, 458441174, 477235510,
					481919117, 493460028, 500169831, 504263775, 508591322, 512244144, 531391596,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(util::from_hex("098364706891b414a55a91ef8686c51ec70d4b779052977009f625630e17a2f1c3".to_string()).unwrap()),
		excess_sig: Signature::from_compact(&util::from_hex("0310ae8f5acaede5ebd62cef36a4979eb7e2cb76cee071a47c3876c1976f0b8373ece849ccaee9b23b0a8d29150d0e1df2bc9028cb80b956a3bef3299b9d369a".to_string()).unwrap()).unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeaturesEx::Coinbase {
			spath: SecuredPath::from_vec(
				util::from_hex(
					"bd3be4bdd2a8d4a7a8559bbcfb5e4705cec320d0ebc633eaaf403c46".to_string(),
				)
				.unwrap(),
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
			"be9f27aa3e8facf0c37f7a0f654dc24c899460fbc7bbd076ffac936407aa2b0e"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"8dcab2576ccb50c76b6604d109224a74aed50a78011c854c5aa6825ca5260ea2"
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
			"be10ae6e874475bb29585a4997f8e42b5afe4ac3a131430036c93b5aaceefd3b"
		);
	}
}
