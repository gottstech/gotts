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
		timestamp: Utc.ymd(2019, 10, 1).and_hms(0, 5, 12),
		prev_root: Hash::from_hex(
			"0000000000000000000535990d39e96feb09c619e310ed7d4cfc1567f1f10a28",
		)
		.unwrap(),
		output_i_root: Hash::from_hex(
			"0a624971e148e56fc50a300945990f5b2abffd41af32fae418005c0fc5f86d68",
		)
		.unwrap(),
		output_ii_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"31526c03ae25dc66671bf0f308c676b2243ab7bf42363301076e429b808d8af3",
		)
		.unwrap(),
		output_i_mmr_size: 1,
		output_ii_mmr_size: 0,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(4)),
			secondary_scaling: 1856,
			nonce: 39,
			proof: Proof {
				nonces: vec![
					4645022, 25254168, 25858467, 32913626, 64966308, 78716899, 85236488, 85594397,
					85777560, 95819995, 104595082, 117710202, 121493192, 154962269, 189241018,
					210311058, 231191674, 241494621, 253981137, 275573426, 279960008, 287988421,
					288525802, 302560875, 302807998, 324594097, 341461658, 346325424, 351548422,
					385825791, 388235246, 395678618, 396896376, 398735887, 409840699, 411631799,
					440127830, 464261277, 465430688, 474881681, 500677785, 502739322,
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
			238, 26, 205, 230, 29, 253, 112, 95, 117, 93, 209, 139, 64, 180, 156, 136, 230, 54,
			165, 159, 185, 108, 239, 132, 33, 237, 187, 48, 236, 198, 9, 45, 49, 81, 161, 67, 114,
			184, 154, 147, 255, 168, 137, 5, 251, 225, 40, 163, 128, 14, 211, 106, 175, 229, 73,
			59, 146, 157, 236, 110, 219, 86, 59, 131,
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
			"e3141a11afb90aa254c9ca9517ddc64970d5f77bde8c75505b18a28f0af5c9cb"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"7c7e997950fa6acaba8e86a1844566417badb83c7a7401a5f4ae2f2b2ee14490"
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
			"a2636b7a5a739dd4da7cfefc535660ac06bbd8c60af141ee9589918610f13ef8"
		);
	}
}
