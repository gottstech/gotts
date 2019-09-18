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
use crate::libtx;
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
		timestamp: Utc.ymd(2019, 7, 3).and_hms(5, 20, 38),
		prev_root: Hash::from_hex(
			"00000000000000000010fc18907643e202ea20da8ec3ecafcb6766cd362031de",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"f6ef9d75a822e8c62d1d3e76160a0f662d2dad625ca8f99573033e8974371acd",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"fead3ef73b04ede3f59bebc5e8c142732a888514da2bd69c3d1d1e35b7a76d79",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"d4952150feda345cb80984181f9d5a648d1531a32ec238f7aa0473025abe4320",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			secondary_scaling: 1856,
			nonce: 202,
			proof: Proof {
				nonces: vec![
					11465334, 24026365, 60162367, 63657469, 64882432, 72984123, 77711864, 81657503,
					96794926, 98932127, 113433617, 152803459, 167459542, 193341988, 193607763,
					194123159, 197565255, 212704173, 216786175, 220551515, 238376739, 248955897,
					249903014, 270453869, 299158780, 302121064, 343343929, 363878154, 369530577,
					403281767, 412710141, 420432006, 443148888, 445313425, 447723747, 474064248,
					484709258, 494216848, 502560810, 504308859, 514584141, 521112611,
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
				"08bcb8f64c77e0f4b22b4f7ce5ddd05be3fbcc1affa90db42a1911baf60b1949cd".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			121, 186, 132, 41, 122, 248, 145, 2, 57, 177, 158, 158, 192, 227, 112, 150, 17, 102,
			120, 66, 160, 113, 132, 88, 167, 142, 66, 22, 121, 107, 124, 228, 211, 61, 191, 77,
			137, 124, 48, 93, 151, 15, 159, 15, 42, 171, 157, 69, 35, 157, 116, 143, 72, 52, 187,
			38, 174, 217, 111, 139, 78, 191, 125, 184,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeaturesEx::Coinbase {
			spath: libtx::proof::SecuredPath::from_vec(
				util::from_hex(
					"0000000023d0443abdc72c6ba9fa96e4e3023ecb48e9879ce709a499492411f2".to_string(),
				)
				.unwrap(),
			),
		},
		commit: Commitment::from_vec(
			util::from_hex(
				"08f6550fdd23d0443abdc72c6ba9fa96e4e3023ecb48e9879ce709a499492411f2".to_string(),
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
			spath: libtx::proof::SecuredPath::from_vec(vec![]), // REPLACE
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
			"2726b97c22b43e7b966fc122787448825977c2c9e50b6df96efe7ce7285f73aa"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"c7e85d043413bd37d5d83b62d9b40e98b5f1a74a972b9ccb61c4d77973f9c41c"
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
