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
//! use gotts_keychain::ExtKeychainPath;
//! use rand::thread_rng;
//!
//! fn main() {
//!     // Generate random key pair
//!     let secp = Secp256k1::with_caps(ContextFlag::Full);
//!
//!     let private_key = SecretKey::new(&mut thread_rng());
//!     let public_key = PublicKey::from_secret_key(&secp, &private_key).unwrap();
//!
//!     // Generate PublicKey address
//! 	let key_id = ExtKeychainPath::new(3, std::u32::MAX>>1, std::u32::MAX>>1, 100, 0).to_identifier();
//!     let address = Address::from_pubkey(&public_key, key_id.last_path_index(), true);
//!     println!("new generated address: {}", address);
//! }
//! ```

use bech32::{self, FromBase32, ToBase32};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::Fail;
use std::fmt;
use std::io::Cursor;
use std::str::FromStr;

use super::core::{self, hash::Hashed};
use super::global::ChainTypes;
use crate::keychain::Identifier;
use crate::util::secp::{self, key::PublicKey};

/// Address error.
#[derive(Clone, PartialEq, Debug, Fail)]
pub enum Error {
	/// HRP(Human Readable Part) error
	#[fail(display = "HRP Error")]
	HRP,
	/// Bech32 encoding error
	#[fail(display = "Bech32: {}", 0)]
	Bech32(bech32::Error),
	/// Secp Error
	#[fail(display = "Secp error")]
	Secp(secp::Error),
	/// The Bech32 payload was empty
	#[fail(display = "Bech32 Payload Empty")]
	EmptyBech32Payload,
	/// The length must be between 2 and 40 bytes in length.
	#[fail(display = "Invalid Length {}", 0)]
	InvalidLength(usize),
	/// Version must be 0 to 16 inclusive
	#[fail(display = "Invalid Version {}", 0)]
	InvalidVersion(u8),
	/// A v0 address must be with a length of 37-bytes
	#[fail(display = "Invalid V0 Length {}", 0)]
	InvalidV0Length(usize),
	/// Bit conversion error
	#[fail(display = "Bit conversion error {}", 0)]
	BitConversionError(String),
	/// Address type error
	#[fail(display = "Incorrect address type")]
	AddressTypeError,
}

impl From<bech32::Error> for Error {
	fn from(inner: bech32::Error) -> Error {
		Error::Bech32(inner)
	}
}

impl From<secp::Error> for Error {
	fn from(inner: secp::Error) -> Error {
		Error::Secp(inner)
	}
}

/// Inner address data of Bech32Addr
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerAddr {
	/// Address with Public Key and its key path, in 37-bytes total.
	PubKeyAddr {
		/// The public key
		pubkey: PublicKey,
		/// The key derivation path (last path only)
		keypath: u32,
	},
}

/// Bech32 address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bech32Addr {
	/// The address version
	pub version: bech32::u5,
	/// The inner address data
	pub inner_addr: InnerAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Default for Address {
	fn default() -> Self {
		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).expect("0<32"),
				inner_addr: InnerAddr::PubKeyAddr {
					pubkey: PublicKey::new(),
					keypath: 0,
				},
			},
			network: ChainTypes::Mainnet,
		}
	}
}

impl Address {
	/// Create an address from a public key.
	/// Considering the address length, we only package the last path of the key derivation paths into the address.
	pub fn from_pubkey(pk: &PublicKey, key_id_last_path: u32, is_mainnet: bool) -> Address {
		let network = match is_mainnet {
			true => ChainTypes::Mainnet,
			false => ChainTypes::Floonet,
		};
		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).expect("0<32"),
				inner_addr: InnerAddr::PubKeyAddr {
					pubkey: pk.clone(),
					keypath: key_id_last_path,
				},
			},
			network,
		}
	}

	/// Get the inner public key of an address, if it's a PubKeyAddr.
	pub fn get_inner_pubkey(&self) -> PublicKey {
		match self.bech32_addr.inner_addr {
			InnerAddr::PubKeyAddr { pubkey, .. } => pubkey,
		}
	}

	/// Get the inner key id of this address.
	/// Considering the address length, only the last path of the key derivation paths stored in the address
	pub fn get_key_id(&self, parent_path: &Identifier) -> Identifier {
		match self.bech32_addr.inner_addr {
			InnerAddr::PubKeyAddr { pubkey: _, keypath } => parent_path.extend(keypath),
		}
	}

	/// Get last path of the inner key id of this address.
	pub fn get_key_id_last_path(&self) -> u32 {
		match self.bech32_addr.inner_addr {
			InnerAddr::PubKeyAddr { pubkey: _, keypath } => keypath,
		}
	}

	/// Get the public key hash of an address, if it's a PubKeyAddr.
	/// The 'hash' here means Blake2b hash.
	pub fn pkh(&self) -> core::hash::Hash {
		match self.bech32_addr.inner_addr {
			InnerAddr::PubKeyAddr { pubkey, .. } => pubkey.serialize_vec(true).hash(),
		}
	}

	/// Serialize to u8 vector: 33-bytes public key || 4-bytes keypath
	pub fn to_vec(&self) -> Vec<u8> {
		let mut wtr: Vec<u8> = Vec::with_capacity(37);
		match self.bech32_addr.inner_addr {
			InnerAddr::PubKeyAddr { pubkey, keypath } => {
				wtr.extend_from_slice(&pubkey.serialize_vec(true));
				wtr.write_u32::<BigEndian>(keypath).unwrap();
			}
		}
		assert_eq!(wtr.len(), 37);
		wtr
	}

	/// Get the address string
	pub fn to_string(&self) -> String {
		let mut data: Vec<bech32::u5> = vec![];
		data.push(self.bech32_addr.version);
		let mut raw = self.to_vec();
		// XOR the path to avoid long zeros
		if raw.len() == 37 {
			raw[33] ^= raw[29];
			raw[34] ^= raw[30];
			raw[35] ^= raw[31];
			raw[36] ^= raw[32];
		}

		// Convert 8-bit data into 5-bit
		let d5 = raw.to_base32();
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
		let (version, mut data): (bech32::u5, Vec<u8>) = {
			let (v, d5) = payload.split_at(1);
			(v[0], FromBase32::from_base32(d5)?)
		};

		// Generic checks.
		if version.to_u8() > 16 {
			return Err(Error::InvalidVersion(version.to_u8()));
		}
		if data.len() < 2 || data.len() > 40 {
			return Err(Error::InvalidLength(data.len()));
		}

		// Specific v0 check.
		if version.to_u8() == 0 && data.len() != 37 {
			return Err(Error::InvalidV0Length(data.len()));
		}

		//println!("raw data: {}", crate::util::to_hex(data.clone()));

		match data.len() {
			37 => {
				// XOR the path to avoid long zeros
				{
					data[33] ^= data[29];
					data[34] ^= data[30];
					data[35] ^= data[31];
					data[36] ^= data[32];
				}
				Ok(Address {
					bech32_addr: Bech32Addr {
						version,
						inner_addr: InnerAddr::PubKeyAddr {
							pubkey: PublicKey::from_slice(&data[0..33])?,
							keypath: {
								let mut rdr = Cursor::new(&data[33..37]);
								rdr.read_u32::<BigEndian>().unwrap()
							},
						},
					},
					network,
				})
			}
			_ => Err(Error::InvalidV0Length(data.len())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::global::ChainTypes;
	use crate::keychain::ExtKeychainPath;
	use crate::util;
	use crate::util::secp::key::PublicKey;

	fn round_trips(addr: &Address) {
		assert_eq!(Address::from_str(&addr.to_string()).unwrap(), *addr,);
		assert_eq!(
			&Address::from_pubkey(
				&addr.get_inner_pubkey(),
				addr.get_key_id_last_path(),
				addr.network == ChainTypes::Mainnet
			),
			addr,
		);
	}

	#[test]
	fn test_p2pkh_from_key() {
		// get address from a public key
		let addr_str = "gs1qqwx4zsv53sts96xftapcs9tefwrlwp4g6nxjhladrhq4wzt3qvkfkugr9nlsy5r2uv";
		let key_id =
			ExtKeychainPath::new(3, std::u32::MAX >> 1, std::u32::MAX >> 1, 100, 0).to_identifier();
		let pubkey = PublicKey::from_slice(
			&util::from_hex(
				"048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b\
				 6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183"
					.to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let addr = Address::from_pubkey(&pubkey, key_id.last_path_index(), true);
		assert_eq!(&addr.to_string(), addr_str);
		let parent_path = key_id.parent_path();
		round_trips(&addr);
		assert_eq!(addr.get_key_id(&parent_path), key_id);

		// same public key as above but in compressed form
		let pubkey = PublicKey::from_slice(
			&util::from_hex(
				"038d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b".to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let addr = Address::from_pubkey(&pubkey, key_id.last_path_index(), true);
		assert_eq!(&addr.to_string(), addr_str);
		round_trips(&addr);

		// another public key
		let pubkey = PublicKey::from_slice(
			&util::from_hex(
				"033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc".to_string(),
			)
			.unwrap(),
		)
		.unwrap();
		let key_id =
			ExtKeychainPath::new(3, std::u32::MAX >> 1, std::u32::MAX >> 1, 200, 0).to_identifier();
		let addr = Address::from_pubkey(&pubkey, key_id.last_path_index(), true);
		assert_eq!(
			&addr.to_string(),
			"gs1qqvau3jpu2t04wy3znghhygrdjqvjxekrvs5vkrqjk6hesvjdj7lmcnvhha6qyyu8wa"
		);
		let parent_path = key_id.parent_path();
		round_trips(&addr);
		assert_eq!(addr.get_key_id(&parent_path), key_id);
	}

	#[test]
	fn test_default_display() {
		let key_id =
			ExtKeychainPath::new(3, std::u32::MAX >> 1, std::u32::MAX >> 1, 100, 0).to_identifier();
		let pubkey_str = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc";
		let pubkey_vec = util::from_hex(pubkey_str.to_string()).unwrap();
		let mut addr = Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).expect("0<32"),
				inner_addr: InnerAddr::PubKeyAddr {
					pubkey: PublicKey::from_slice(&pubkey_vec).unwrap(),
					keypath: key_id.last_path_index(),
				},
			},
			network: ChainTypes::Mainnet,
		};
		assert_eq!(Address::from_str(&addr.to_string()).unwrap(), addr,);
		println!("pubkey: {}, mainnet address: {}", pubkey_str, addr);
		addr.network = ChainTypes::Floonet;
		println!("pubkey: {}, floonet address: {}", pubkey_str, addr);
	}

	#[test]
	fn test_vectors() {
		let valid_vectors = [
			(
				"gs1qqvau3jpu2t04wy3znghhygrdjqvjxekrvs5vkrqjk6hesvjdj7lmcnvhhlvqdfrsjt",
				"cef5ad3c9482d1e831ceacadbd53469198f33f10b3822cfef77f33a3dc9b9dd8",
			),
			(
				"TS1QQVAU3JPU2T04WY3ZNGHHYGRDJQVJXEKRVS5VKRQJK6HESVJDJ7LMCNVHHLVQ93U3FD",
				"cef5ad3c9482d1e831ceacadbd53469198f33f10b3822cfef77f33a3dc9b9dd8",
			),
		];

		for vector in &valid_vectors {
			let addr = Address::from_str(vector.0).unwrap();
			assert_eq!(&addr.pkh().to_hex(), vector.1);
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
}
