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
use crate::keychain::BlindingFactor;

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
		timestamp: Utc.ymd(2019, 9, 27).and_hms(2, 42, 33),
		prev_root: Hash::from_hex(
			"00000000000000000000d97a46904026bf766331b67353e1c1940b842161be7d",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"0a624971e148e56fc50a300945990f5b2abffd41af32fae418005c0fc5f86d68",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"b719cc8a5a3c9c0cc07d8f67b718cff2f02e092b0eef21141fd521ffd0fd59b9",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(8)),
			secondary_scaling: 1856,
			nonce: 59,
			proof: Proof {
				nonces: vec![
					9127304, 25854211, 27712386, 33301435, 33552282, 62407143, 88220813, 105154708,
					177419736, 180255473, 180359597, 211559831, 224286746, 226623527, 227058743,
					253994566, 275084370, 284214898, 302576573, 314645120, 336035389, 340323119,
					353410924, 355820657, 356241491, 395353026, 396613984, 421245907, 428321543,
					436886389, 438015553, 440628804, 448863753, 450952214, 454581257, 472946258,
					473736645, 485091870, 494984574, 497334904, 504738640, 522484747,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex(
				"0973513433682b8f4224a7a1bf387755a0642b54ca129eb4bc2946bd8e83fb54b4".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			238, 224, 5, 44, 37, 160, 130, 69, 162, 152, 204, 161, 121, 234, 117, 33, 224, 219,
			104, 16, 97, 191, 140, 171, 162, 59, 222, 160, 36, 172, 138, 149, 138, 216, 201, 60,
			238, 148, 107, 105, 157, 42, 150, 165, 166, 188, 162, 74, 245, 198, 95, 102, 189, 78,
			35, 67, 77, 169, 224, 25, 93, 205, 45, 174,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeaturesEx::Coinbase {
			spath: SecuredPath::from_vec(
				util::from_hex(
					"9c9af651f2111dc5d529a760d5c42ea24d572589453f38982a9984c7".to_string(),
				)
				.unwrap(),
			),
		},
		commit: Commitment::from_vec(
			util::from_hex(
				"0973513433682b8f4224a7a1bf387755a0642b54ca129eb4bc2946bd8e83fb54b4".to_string(),
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
		output_root: Hash::default(),                      // REPLACE
		range_proof_root: Hash::default(),                 // REPLACE
		kernel_root: Hash::default(),                      // REPLACE
		total_kernel_offset: BlindingFactor::zero(),       // REPLACE
		output_mmr_size: 1,
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
			"b5aaad3823cf605787fbe3d30f47d145652ac71c87c75203a5cec813bda932f6"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"23f19d9e53bcc880170781748858e82e3271e569b945b5d6490b45925ba86094"
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
			"83cadf68794eb38fe195bd780b08e9b9cd5ff15d9f24aaf71d7b432622167d9a"
		);
	}
}
