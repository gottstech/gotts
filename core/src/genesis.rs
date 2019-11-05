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
		timestamp: Utc.ymd(2019, 11, 5).and_hms(14, 36, 50),
		prev_root: Hash::from_hex(
			"000000000000000000003a3b4073aa1f155cb99705cc62d0d052bf318072bce4",
		)
		.unwrap(),
		output_i_root: Hash::from_hex(
			"8eb4296382c7feea98f851ea1724740fcc5484ad0738fd226258ec815ecd149d",
		)
		.unwrap(),
		output_ii_root: Hash::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"fb4050618f85eeb04ceaf2635141bf340194c8d1f89fc681e00d779fcd691ab1",
		)
		.unwrap(),
		output_i_mmr_size: 1,
		output_ii_mmr_size: 0,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(4)),
			secondary_scaling: 1856,
			nonce: 28,
			proof: Proof {
				nonces: vec![
					650230, 6926521, 31137998, 50236734, 58055146, 58753112, 71371672, 84172708,
					114107050, 121157144, 126585876, 126658184, 129713219, 168517429, 172184610,
					188388637, 211309123, 211769029, 219409258, 221959403, 267287292, 280493025,
					281365801, 286490796, 312020445, 326722039, 347430695, 374128146, 375977322,
					384363953, 397205970, 408064646, 411176527, 443626967, 445750928, 457181541,
					471166499, 473873136, 479963913, 506757685, 524530986, 527402994,
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
				"09603078dc4784b57ae301efd16ea6e1702676ed12e8a06defed2d6658de1ce013".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			162, 233, 186, 49, 107, 65, 160, 171, 85, 11, 99, 95, 9, 129, 169, 229, 243, 8, 175,
			124, 74, 85, 131, 237, 222, 30, 17, 193, 72, 105, 89, 194, 96, 24, 37, 154, 54, 184,
			210, 12, 213, 130, 144, 63, 181, 232, 95, 75, 167, 245, 154, 171, 76, 2, 46, 189, 170,
			183, 99, 41, 214, 252, 80, 247,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeaturesEx::Coinbase {
			spath: SecuredPath::from_vec(
				util::from_hex(
					"0731dab0f44bc53769cad8ff51e21ea8841160c0f7096cace42797f5".to_string(),
				)
				.unwrap(),
			),
		},
		commit: Commitment::from_vec(
			util::from_hex(
				"09603078dc4784b57ae301efd16ea6e1702676ed12e8a06defed2d6658de1ce013".to_string(),
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
