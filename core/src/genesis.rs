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
		timestamp: Utc.ymd(2019, 11, 6).and_hms(0, 53, 35),
		prev_root: Hash::from_hex(
			"0000000000000000000c0e600d0acb6bbdea738f9f5d6d49fc82318da427f11b",
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
			"3c2d85c54a0b09306d67cd8a7daa15bb557ed28b9ddb0007aac802ab45d58bff",
		)
		.unwrap(),
		output_i_mmr_size: 1,
		output_ii_mmr_size: 0,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(4)),
			secondary_scaling: 1856,
			nonce: 27,
			proof: Proof {
				nonces: vec![
					17476596, 32443702, 56145007, 58141318, 104365753, 107360137, 127175005,
					138039798, 139057522, 166814828, 169308347, 195051560, 214591286, 218391532,
					222045925, 230418031, 237776292, 243154286, 249848739, 276514698, 277972881,
					286002285, 307797231, 318277568, 321115456, 328512216, 330895080, 340557176,
					348715841, 372128343, 391881755, 396501951, 410088557, 429215845, 450829244,
					464140808, 464624790, 469242887, 480164419, 517525540, 524896010, 534173509,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(util::from_hex("09603078dc4784b57ae301efd16ea6e1702676ed12e8a06defed2d6658de1ce013".to_string()).unwrap()),
		excess_sig: Signature::from_compact(&util::from_hex("cf4a1ec0431d738cd79daf54b70ee1208799702012d12433ea5cdec5960a74bd91d76bfc8ab82456b0aa523954d1036d94c4d7b117e94ce57f56f38d3bdb9519".to_string()).unwrap()).unwrap(),
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
			"5c31e17e2d506f9876ca10e498ac4ae6a60eb2fec10bde3ba8482e0d76365735"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"eb9f99417c8f57600889f6bf1a1798b85cf82d8af089ec32c928001e8111a6b9"
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
			"0c2637a6ac751ef15dea26022f45f5d2131dd2dd7210387384f5f443931be277"
		);
	}
}
