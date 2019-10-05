// Copyright 2019 The Gotts Developers
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

//! Address
//!
//! Support for P2PKH Bech32 address
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! use gotts_util;
//!	use gotts_util::secp::key::{SecretKey, PublicKey};
//!	use gotts_util::secp::{ContextFlag, Secp256k1};
//! use gotts_core::address::Address;
//! use gotts_core::global::ChainTypes;
//! use rand::thread_rng;
//!
//! fn main() {
//!     // Generate random key pair
//!     let secp = Secp256k1::with_caps(ContextFlag::Full);
//!
//!     let private_key = SecretKey::new(&secp, &mut thread_rng());
//!     let public_key = PublicKey::from_secret_key(&secp, &private_key).unwrap();
//!
//!     // Generate pay-to-pubkey-hash address
//!     let address = Address::from_pubkey(&public_key, ChainTypes::Mainnet);
//!     println!("new generated address: {}", address);
//! }
//! ```

use bech32::{self, ToBase32};
use bitcoin_hashes::{self, hash160, Hash};
use failure::Fail;
use std::fmt;
use std::str::FromStr;

use super::global::ChainTypes;
use super::ser::Hash160Writeable;
use crate::util::secp::key::PublicKey;

/// Address error.
#[derive(Clone, Debug, Fail, PartialEq)]
pub enum Error {
	/// HRP(Human Readable Part) error
	#[fail(display = "HRP Error")]
	HRP,
	/// Bech32 encoding error
	#[fail(display = "Bech32: {}", 0)]
	Bech32(bech32::Error),
	/// Hash160 error
	#[fail(display = "Hash160: {}", 0)]
	Hash160(bitcoin_hashes::Error),
	/// The Bech32 payload was empty
	#[fail(display = "Bech32 Payload Empty")]
	EmptyBech32Payload,
	/// The length must be between 2 and 40 bytes in length.
	#[fail(display = "Invalid Length {}", 0)]
	InvalidLength(usize),
	/// Version must be 0 to 16 inclusive
	#[fail(display = "Invalid Version {}", 0)]
	InvalidVersion(u8),
	/// A v0 address must be with a length of 20
	#[fail(display = "Invalid V0 Length {}", 0)]
	InvalidV0Length(usize),
	/// Bit conversion error
	#[fail(display = "Bit conversion error {}", 0)]
	BitConversionError(String),
}

impl From<bech32::Error> for Error {
	fn from(inner: bech32::Error) -> Error {
		Error::Bech32(inner)
	}
}

impl From<bitcoin_hashes::Error> for Error {
	fn from(inner: bitcoin_hashes::Error) -> Error {
		Error::Hash160(inner)
	}
}

/// Bech32 address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bech32Addr {
	/// The address version
	pub version: bech32::u5,
	/// The public key hash
	pub pubkey_hash: hash160::Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A Bitcoin address
pub struct Address {
	/// The type of the address
	pub bech32_addr: Bech32Addr,
	/// The network on which this address is usable
	pub network: ChainTypes,
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_string())
	}
}

impl Address {
	/// Create an address from a public key
	pub fn from_pubkey(pk: &PublicKey, network: ChainTypes) -> Address {
		let mut hash_engine = hash160::Hash::engine();
		pk.write_into(&mut hash_engine).unwrap();

		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).expect("0<32"),
				pubkey_hash: hash160::Hash::from_engine(hash_engine),
			},
			network,
		}
	}

	/// Calculate Public-Key-Hash, i.e. RIPEMD160(SHA256(PublicKey)).
	pub fn pkh(pk: &PublicKey) -> hash160::Hash {
		let mut hash_engine = hash160::Hash::engine();
		pk.write_into(&mut hash_engine).unwrap();

		hash160::Hash::from_engine(hash_engine)
	}

	/// Create an address from a public key hash
	pub fn from_pubkeyhash(pubkey_hash: hash160::Hash, network: ChainTypes) -> Address {
		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).expect("0<32"),
				pubkey_hash,
			},
			network,
		}
	}

	/// Get the public key hash of an address
	pub fn get_pubkeyhash(&self) -> hash160::Hash {
		self.bech32_addr.pubkey_hash
	}

	/// Get the address string
	pub fn to_string(&self) -> String {
		let mut data: Vec<bech32::u5> = Vec::with_capacity(33);
		data.push(self.bech32_addr.version);
		// Convert 8-bit data into 5-bit
		let d5 = self.bech32_addr.pubkey_hash.to_vec().to_base32();
		data.extend_from_slice(&d5);
		let hrp = match self.network {
			ChainTypes::Mainnet => "gs",
			ChainTypes::Floonet => "ts",
			_ => "ts",
		};
		bech32::encode(hrp, data).unwrap()
	}
}

impl FromStr for Address {
	type Err = Error;

	fn from_str(s: &str) -> Result<Address, Error> {
		let (hrp, payload) = bech32::decode(s)?;
		let network = match hrp.as_str() {
			// Note: Upper or lowercase is allowed but NOT mixed case.
			"gs" | "GS" => ChainTypes::Mainnet,
			"ts" | "TS" => ChainTypes::Floonet,
			_ => return Err(Error::HRP),
		};

		if payload.len() == 0 {
			return Err(Error::EmptyBech32Payload);
		}

		// Get the version and data (converted from 5-bit to 8-bit)
		let (version, data): (bech32::u5, Vec<u8>) = {
			let (v, d5) = payload.split_at(1);
			(v[0], bech32::FromBase32::from_base32(d5)?)
		};

		// Generic checks.
		if version.to_u8() > 16 {
			return Err(Error::InvalidVersion(version.to_u8()));
		}
		if data.len() < 2 || data.len() > 40 {
			return Err(Error::InvalidLength(data.len()));
		}

		// Specific v0 check.
		if version.to_u8() == 0 && data.len() != 20 {
			return Err(Error::InvalidV0Length(data.len()));
		}

		Ok(Address {
			bech32_addr: Bech32Addr {
				version,
				pubkey_hash: hash160::Hash::from_slice(&data)?,
			},
			network,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::util;
	use crate::util::secp::key::PublicKey;
	use crate::util::secp::{ContextFlag, Secp256k1};
	use bitcoin_hashes::{self, hash160, hex::ToHex, Hash};

	fn round_trips(addr: &Address) {
		assert_eq!(Address::from_str(&addr.to_string()).unwrap(), *addr,);
		assert_eq!(
			&Address::from_pubkeyhash(addr.get_pubkeyhash(), addr.network.clone()),
			addr,
		);
	}

	#[test]
	fn test_p2pkh_from_key() {
		let secp = Secp256k1::with_caps(ContextFlag::None);

		// get address from a public key
		let pubkey = PublicKey::from_slice(
			&secp,
			&util::from_hex(
				r##"04
				8d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b
                6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183"##
					.to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let addr = Address::from_pubkey(&pubkey, ChainTypes::Mainnet);
		assert_eq!(
			&addr.to_string(),
			"gs1qps788lr4wqn8s7g0j9zxn200cnewqckpm4d088"
		);

		// same public key as above but in compressed form
		let pubkey = PublicKey::from_slice(
			&secp,
			&util::from_hex(
				"038d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b".to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let addr = Address::from_pubkey(&pubkey, ChainTypes::Mainnet);
		assert_eq!(
			&addr.to_string(),
			"gs1qps788lr4wqn8s7g0j9zxn200cnewqckpm4d088"
		);

		// another address
		let pubkey = PublicKey::from_slice(
			&secp,
			&util::from_hex(
				"03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f".to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let addr = Address::from_pubkey(&pubkey, ChainTypes::Floonet);
		assert_eq!(
			&addr.to_string(),
			"ts1qwp9grvnlqqek66c4p9vtwaqutqrm492qrtn27h"
		);

		// from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
		let pubkey = PublicKey::from_slice(
			&secp,
			&util::from_hex(
				"033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc".to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let addr = Address::from_pubkey(&pubkey, ChainTypes::Mainnet);
		assert_eq!(
			&addr.to_string(),
			"gs1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw"
		);

		round_trips(&addr);
	}

	#[test]
	fn test_non_existent_version() {
		let version: u8 = 13;
		// 20-byte hash160
		let hash_str = "751e76e8199196d454941c45d1b3a323f1433bd6";
		let pubkey_hash = util::from_hex(hash_str.to_string()).unwrap();
		let mut addr = Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(version).expect("13<32"),
				pubkey_hash: hash160::Hash::from_slice(&pubkey_hash).unwrap(),
			},
			network: ChainTypes::Mainnet,
		};
		assert_eq!(Address::from_str(&addr.to_string()).unwrap(), addr,);

		// restore as the version_0
		addr.bech32_addr.version = bech32::u5::try_from_u8(0).expect("0<32");
		println!("hash160: {}, mainnet address: {}", hash_str, addr);
		addr.network = ChainTypes::Floonet;
		println!("hash160: {}, floonet address: {}", hash_str, addr);
	}

	#[test]
	fn test_vectors() {
		let valid_vectors = [
			(
				"GS1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KJC4G9H",
				"751e76e8199196d454941c45d1b3a323f1433bd6",
			),
			(
				"gs1qw508d6qejxtdg4y5r3zarvary0c5xw7kjc4g9h",
				"751e76e8199196d454941c45d1b3a323f1433bd6",
			),
			(
				"TS1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7K7TKY9D",
				"751e76e8199196d454941c45d1b3a323f1433bd6",
			),
			(
				"ts1qw508d6qejxtdg4y5r3zarvary0c5xw7k7tky9d",
				"751e76e8199196d454941c45d1b3a323f1433bd6",
			),
		];
		for vector in &valid_vectors {
			let addr = Address::from_str(vector.0).unwrap();
			assert_eq!(&addr.bech32_addr.pubkey_hash.to_hex(), vector.1);
			round_trips(&addr);
		}

		let invalid_vectors = [
			"ts1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
			"gs1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
			"GS13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
			"ts1rw5uspcuh",
			"ts10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
			"TS1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
			"ts1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
			"gs1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
			"ts1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
			"gs1gmk9yu",
		];
		for vector in &invalid_vectors {
			assert!(Address::from_str(vector).is_err());
		}
	}

	#[test]
	#[cfg(feature = "serde")]
	fn test_json_serialize() {
		use serde_json;

		let addr = Address::from_str("gs1qw508d6qejxtdg4y5r3zarvary0c5xw7kjc4g9h").unwrap();
		let json = serde_json::to_value(&addr).unwrap();
		assert_eq!(
			json,
			serde_json::Value::String("gs1qw508d6qejxtdg4y5r3zarvary0c5xw7kjc4g9h".to_owned())
		);
		let into: Address = serde_json::from_value(json).unwrap();
		assert_eq!(addr.to_string(), into.to_string());
		assert_eq!(
			&addr.bech32_addr.pubkey_hash.to_hex(),
			"751e76e8199196d454941c45d1b3a323f1433bd6"
		);
	}
}
