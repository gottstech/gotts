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

use crate::core;
use crate::pow::{Difficulty, Proof, ProofOfWork};
use crate::util;
use crate::util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
use crate::util::secp::pedersen::{Commitment, RangeProof};
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
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"08f6550fdd23d0443abdc72c6ba9fa96e4e3023ecb48e9879ce709a499492411f2".to_string(),
			)
			.unwrap(),
		),
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				208, 8, 199, 126, 177, 50, 234, 116, 12, 166, 81, 247, 95, 144, 58, 116, 62, 29,
				183, 59, 41, 20, 130, 82, 229, 245, 147, 92, 196, 189, 245, 122, 252, 232, 233,
				148, 198, 90, 208, 200, 104, 254, 238, 82, 83, 47, 91, 205, 147, 9, 177, 253, 253,
				249, 185, 113, 58, 12, 177, 210, 198, 41, 245, 139, 15, 210, 230, 157, 85, 214,
				240, 171, 191, 122, 17, 140, 34, 225, 169, 77, 45, 123, 183, 212, 65, 226, 59, 201,
				179, 171, 92, 74, 125, 12, 5, 213, 49, 193, 91, 186, 32, 170, 60, 234, 239, 209,
				195, 78, 227, 67, 172, 85, 206, 190, 166, 202, 236, 108, 92, 1, 87, 49, 250, 88,
				91, 221, 198, 184, 224, 224, 38, 88, 202, 210, 184, 74, 85, 151, 239, 54, 156, 101,
				87, 240, 182, 174, 93, 160, 173, 195, 58, 135, 233, 170, 72, 150, 66, 22, 116, 100,
				176, 194, 64, 73, 166, 79, 254, 35, 127, 70, 205, 21, 217, 113, 101, 78, 201, 21,
				255, 157, 176, 140, 131, 208, 70, 64, 210, 182, 192, 175, 74, 102, 225, 103, 225,
				161, 150, 193, 118, 65, 213, 140, 238, 247, 144, 39, 185, 68, 91, 120, 118, 72,
				235, 150, 80, 55, 149, 240, 167, 220, 66, 236, 165, 127, 147, 33, 75, 97, 227, 73,
				88, 235, 17, 95, 100, 84, 220, 81, 194, 56, 170, 56, 114, 44, 46, 63, 190, 22, 85,
				86, 39, 127, 208, 234, 34, 111, 113, 129, 182, 139, 82, 172, 212, 162, 102, 7, 60,
				30, 186, 80, 118, 137, 121, 188, 14, 61, 73, 103, 43, 167, 52, 28, 179, 101, 122,
				225, 142, 38, 146, 9, 216, 58, 215, 133, 129, 217, 200, 74, 210, 116, 250, 76, 53,
				145, 35, 202, 34, 65, 234, 78, 22, 65, 252, 94, 222, 254, 116, 83, 46, 123, 240,
				232, 50, 9, 9, 44, 53, 41, 153, 210, 96, 130, 252, 255, 63, 214, 216, 81, 41, 183,
				24, 177, 161, 248, 23, 176, 34, 183, 35, 109, 252, 27, 102, 207, 3, 70, 29, 93,
				252, 124, 144, 29, 238, 113, 108, 204, 175, 208, 79, 55, 127, 185, 229, 198, 124,
				190, 142, 249, 131, 239, 56, 32, 116, 120, 124, 16, 128, 88, 120, 173, 120, 201,
				189, 64, 157, 42, 160, 96, 157, 65, 94, 148, 112, 224, 213, 204, 125, 116, 19, 61,
				197, 70, 245, 57, 186, 140, 43, 58, 199, 123, 17, 225, 129, 133, 60, 190, 47, 187,
				25, 24, 180, 95, 112, 94, 208, 225, 103, 186, 147, 190, 31, 160, 75, 148, 162, 217,
				151, 101, 182, 65, 52, 180, 3, 57, 144, 104, 167, 131, 47, 196, 250, 233, 18, 44,
				92, 60, 158, 146, 39, 69, 17, 119, 166, 133, 94, 215, 95, 2, 215, 160, 249, 132,
				33, 217, 232, 32, 193, 187, 218, 226, 54, 107, 42, 30, 44, 102, 246, 76, 253, 145,
				153, 214, 250, 75, 213, 211, 12, 216, 233, 61, 240, 210, 85, 151, 170, 5, 194, 6,
				22, 44, 189, 19, 44, 84, 185, 141, 84, 205, 213, 81, 43, 137, 84, 204, 154, 23,
				169, 34, 7, 61, 140, 245, 243, 8, 232, 238, 80, 8, 89, 20, 97, 196, 154, 102, 171,
				231, 247, 64, 244, 242, 166, 161, 89, 224, 73, 204, 210, 127, 174, 2, 228, 27, 68,
				115, 124, 98, 16, 134, 102, 46, 255, 167, 86, 154, 210, 110, 227, 35, 138, 132, 41,
				195, 12, 167, 79, 242, 221, 131, 211, 113, 40, 99, 68, 149, 214, 72, 175, 202, 235,
				234, 210, 108, 217, 122, 36, 6, 177, 0, 189, 236, 70, 98, 57, 131, 163, 106, 226,
				239, 123, 85, 222, 41, 75, 235, 20, 195, 112, 60, 78, 121, 50, 93, 182, 163, 111,
				238, 72, 189, 56, 187, 109, 251, 215, 237, 146, 51, 17, 126, 89, 152, 47, 160, 210,
				113, 130, 232, 108, 78, 204, 134, 66, 192, 148, 54, 63,
			],
		},
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
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(vec![]), // REPLACE
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [0; SINGLE_BULLET_PROOF_SIZE], // REPLACE
		},
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
			"0a481e2cd2867d8bb70962c8cce31809c09c320e44b5f7a998467cbd355a57f7"
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
			"0f616bd745d436d9ad22a6d4c8710c43b538aa826cb7e394548e24247850ea60"
		);
	}
}
