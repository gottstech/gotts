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

use failure::Fail;
use rand::thread_rng;
use std::cmp::min;
/// Keychain trait and its main supporting types. The Identifier is a
/// semi-opaque structure (just bytes) to track keys within the Keychain.
/// BlindingFactor is a useful wrapper around a private key to help with
/// commitment generation.
use std::fmt;
use std::io::Cursor;
use std::ops::Add;

use crate::extkey_bip32::{self, ChildNumber};
use serde::{de, ser}; //TODO: Convert errors to use ErrorKind

use crate::util;
use crate::util::secp::constants::SECRET_KEY_SIZE;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::util::secp::{self, Message, Secp256k1, Signature};
use crate::util::static_secp_instance;
use zeroize::Zeroize;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

// Size of an identifier in bytes
pub const IDENTIFIER_SIZE: usize = 17;

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize, Fail)]
pub enum Error {
	/// libsecp internal error
	#[fail(display = "Keychain libsecp internal error: {}", _0)]
	Secp(secp::Error),
	/// KeyDerivation error
	#[fail(display = "Keychain KeyDerivation error: {}", _0)]
	KeyDerivation(extkey_bip32::Error),
	/// InvalidIdentifier error
	#[fail(display = "Keychain InvalidIdentifier error")]
	InvalidIdentifier,
	/// FromHexError error
	#[fail(display = "Keychain FromHexError error: {}", _0)]
	FromHexError(String),
	/// Transaction error
	#[fail(display = "Keychain Transaction error: {}", _0)]
	Transaction(String),
	/// RangeProof error
	#[fail(display = "Keychain RangeProof error: {}", _0)]
	RangeProof(String),
	/// SwitchCommitment error
	#[fail(display = "Keychain SwitchCommitment error")]
	SwitchCommitment,
	/// Generic Error
	#[fail(display = "Keychain Generic error: {}", _0)]
	Generic(String),
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

impl From<hex::FromHexError> for Error {
	fn from(e: hex::FromHexError) -> Error {
		Error::FromHexError(e.to_string())
	}
}

impl From<extkey_bip32::Error> for Error {
	fn from(e: extkey_bip32::Error) -> Error {
		Error::KeyDerivation(e)
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Ord, Hash, PartialOrd)]
pub struct Identifier([u8; IDENTIFIER_SIZE]);

impl ser::Serialize for Identifier {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: ser::Serializer,
	{
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> de::Deserialize<'de> for Identifier {
	fn deserialize<D>(deserializer: D) -> Result<Identifier, D::Error>
	where
		D: de::Deserializer<'de>,
	{
		deserializer.deserialize_str(IdentifierVisitor)
	}
}

struct IdentifierVisitor;

impl<'de> de::Visitor<'de> for IdentifierVisitor {
	type Value = Identifier;

	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("an identifier")
	}

	fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
	where
		E: de::Error,
	{
		let identifier = Identifier::from_hex(s).unwrap();
		Ok(identifier)
	}
}

impl Identifier {
	pub fn zero() -> Identifier {
		Identifier::from_bytes(&[0; IDENTIFIER_SIZE]).unwrap()
	}

	pub fn from_path(path: &ExtKeychainPath) -> Identifier {
		path.to_identifier()
	}

	pub fn to_path(&self) -> ExtKeychainPath {
		ExtKeychainPath::from_identifier(&self)
	}

	pub fn extend(&self, d: u32) -> Identifier {
		self.to_path().extend(d).to_identifier()
	}

	pub fn to_value_path(&self, value: u64, w: i64) -> ValueExtKeychainPath {
		ValueExtKeychainPath {
			value,
			w,
			ext_keychain_path: self.to_path(),
		}
	}

	/// output the path itself, for insertion into bulletproof
	/// recovery processes can gottsd through possiblities to find the
	/// correct length if required
	pub fn serialize_path(&self) -> [u8; IDENTIFIER_SIZE - 1] {
		let mut retval = [0u8; IDENTIFIER_SIZE - 1];
		retval.copy_from_slice(&self.0[1..IDENTIFIER_SIZE]);
		retval
	}

	/// restore from a serialized path
	pub fn from_serialized_path(len: u8, p: &[u8]) -> Identifier {
		let mut id = [0; IDENTIFIER_SIZE];
		id[0] = len;
		for i in 1..IDENTIFIER_SIZE {
			id[i] = p[i - 1];
		}
		Identifier(id)
	}

	/// Return the parent path
	pub fn parent_path(&self) -> Identifier {
		let mut p = ExtKeychainPath::from_identifier(&self);
		if p.depth > 0 {
			p.path[p.depth as usize - 1] = ChildNumber::from(0);
			p.depth = p.depth - 1;
		}
		Identifier::from_path(&p)
	}
	pub fn from_bytes(bytes: &[u8]) -> Result<Identifier, Error> {
		let mut identifier = [0; IDENTIFIER_SIZE];
		for i in 0..min(IDENTIFIER_SIZE, bytes.len()) {
			identifier[i] = bytes[i];
		}
		if identifier[0] > 4 {
			return Err(Error::InvalidIdentifier);
		}
		Ok(Identifier(identifier))
	}

	pub fn to_bytes(&self) -> [u8; IDENTIFIER_SIZE] {
		self.0.clone()
	}

	pub fn from_hex(hex: &str) -> Result<Identifier, Error> {
		let bytes = util::from_hex(hex.to_string())?;
		Identifier::from_bytes(&bytes)
	}

	pub fn to_hex(&self) -> String {
		util::to_hex(self.0.to_vec())
	}

	pub fn to_bip_32_string(&self) -> String {
		let p = ExtKeychainPath::from_identifier(&self);
		let mut retval = String::from("m");
		assert!(p.path.len() >= p.depth as usize);
		for i in 0..p.depth {
			retval.push_str(&format!("/{}", <u32>::from(p.path[i as usize])));
		}
		retval
	}
}

impl AsRef<[u8]> for Identifier {
	fn as_ref(&self) -> &[u8] {
		&self.0.as_ref()
	}
}

impl ::std::fmt::Debug for Identifier {
	fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
		write!(f, "{}(", stringify!(Identifier))?;
		write!(f, "{}", self.to_hex())?;
		write!(f, ")")
	}
}

impl fmt::Display for Identifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_hex())
	}
}

#[derive(Default, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct BlindingFactor([u8; SECRET_KEY_SIZE]);

// Dummy `Debug` implementation that prevents secret leakage.
impl fmt::Debug for BlindingFactor {
	fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "BlindingFactor(<secret key hidden>)")
	}
}

impl AsRef<[u8]> for BlindingFactor {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Add for BlindingFactor {
	type Output = Result<BlindingFactor, Error>;

	// Convenient (and robust) way to add two blinding_factors together.
	// Handles "zero" blinding_factors correctly.
	//
	// let bf = (bf1 + bf2)?;
	//
	fn add(self, other: BlindingFactor) -> Self::Output {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let keys = vec![self, other]
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key().ok())
			.collect::<Vec<_>>();

		if keys.is_empty() {
			Ok(BlindingFactor::zero())
		} else {
			let sum = secp.blind_sum(keys, vec![])?;
			Ok(BlindingFactor::from_secret_key(sum))
		}
	}
}

impl BlindingFactor {
	pub fn from_secret_key(skey: secp::key::SecretKey) -> BlindingFactor {
		BlindingFactor::from_slice(&skey.as_ref())
	}

	pub fn from_slice(data: &[u8]) -> BlindingFactor {
		let mut blind = [0; SECRET_KEY_SIZE];
		for i in 0..min(SECRET_KEY_SIZE, data.len()) {
			blind[i] = data[i];
		}
		BlindingFactor(blind)
	}

	pub fn zero() -> BlindingFactor {
		BlindingFactor::from_secret_key(secp::key::ZERO_KEY)
	}

	pub fn to_hex(&self) -> String {
		util::to_hex(self.0.to_vec())
	}

	pub fn from_hex(hex: &str) -> Result<BlindingFactor, Error> {
		let bytes = util::from_hex(hex.to_string()).unwrap();
		Ok(BlindingFactor::from_slice(&bytes))
	}

	pub fn secret_key(&self) -> Result<secp::key::SecretKey, Error> {
		if *self == BlindingFactor::zero() {
			// TODO - need this currently for tx tests
			// the "zero" secret key is not actually a valid secret_key
			// and secp lib checks this
			Ok(secp::key::ZERO_KEY)
		} else {
			secp::key::SecretKey::from_slice(&self.0).map_err(|e| Error::Secp(e))
		}
	}

	/// Split a blinding_factor (aka secret_key) into a pair of
	/// blinding_factors. We use one of these (k1) to sign the tx_kernel (k1G)
	/// and the other gets aggregated in the block_header as the "offset".
	/// This prevents an actor from being able to sum a set of inputs, outputs
	/// and kernels from a block to identify and reconstruct a particular tx
	/// from a block. You would need both k1, k2 to do this.
	pub fn split(&self, secp: &Secp256k1) -> Result<SplitBlindingFactor, Error> {
		let skey_1 = secp::key::SecretKey::new(&mut thread_rng());

		// use blind_sum to subtract skey_1 from our key (to give k = k1 + k2)
		let skey = self.secret_key()?;
		let skey_2 = secp.blind_sum(vec![skey], vec![skey_1.clone()])?;

		let blind_1 = BlindingFactor::from_secret_key(skey_1);
		let blind_2 = BlindingFactor::from_secret_key(skey_2);

		Ok(SplitBlindingFactor { blind_1, blind_2 })
	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitBlindingFactor {
	pub blind_1: BlindingFactor,
	pub blind_2: BlindingFactor,
}

/// Accumulator to compute the sum of blinding factors. Keeps track of each
/// factor as well as the "sign" with which they should be combined.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindSum {
	pub positive_key_ids: Vec<ValueExtKeychainPath>,
	pub negative_key_ids: Vec<ValueExtKeychainPath>,
	pub positive_blinding_factors: Vec<BlindingFactor>,
	pub negative_blinding_factors: Vec<BlindingFactor>,
}

impl BlindSum {
	/// Creates a new blinding factor sum.
	pub fn new() -> BlindSum {
		BlindSum {
			positive_key_ids: vec![],
			negative_key_ids: vec![],
			positive_blinding_factors: vec![],
			negative_blinding_factors: vec![],
		}
	}

	pub fn add_key_id(mut self, path: ValueExtKeychainPath) -> BlindSum {
		self.positive_key_ids.push(path);
		self
	}

	pub fn sub_key_id(mut self, path: ValueExtKeychainPath) -> BlindSum {
		self.negative_key_ids.push(path);
		self
	}

	/// Adds the provided key to the sum of blinding factors.
	pub fn add_blinding_factor(mut self, blind: BlindingFactor) -> BlindSum {
		self.positive_blinding_factors.push(blind);
		self
	}

	/// Subtracts the provided key to the sum of blinding factors.
	pub fn sub_blinding_factor(mut self, blind: BlindingFactor) -> BlindSum {
		self.negative_blinding_factors.push(blind);
		self
	}
}

/// Encapsulates a max 4-level deep BIP32 path, which is the most we can
/// currently fit into a rangeproof message. The depth encodes how far the
/// derivation depths go and allows differentiating paths. As m/0, m/0/0
/// or m/0/0/0/0 result in different derivations, a path needs to encode
/// its maximum depth.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ExtKeychainPath {
	pub depth: u8,
	pub path: [extkey_bip32::ChildNumber; 4],
}

impl ExtKeychainPath {
	/// Return a new chain path with given derivation and depth
	pub fn new(depth: u8, d0: u32, d1: u32, d2: u32, d3: u32) -> ExtKeychainPath {
		ExtKeychainPath {
			depth,
			path: [
				ChildNumber::from(d0),
				ChildNumber::from(d1),
				ChildNumber::from(d2),
				ChildNumber::from(d3),
			],
		}
	}

	/// from an Identifier [manual deserialization]
	pub fn from_identifier(id: &Identifier) -> ExtKeychainPath {
		let mut rdr = Cursor::new(id.0.to_vec());
		ExtKeychainPath {
			depth: rdr.read_u8().unwrap(),
			path: [
				ChildNumber::from(rdr.read_u32::<BigEndian>().unwrap()),
				ChildNumber::from(rdr.read_u32::<BigEndian>().unwrap()),
				ChildNumber::from(rdr.read_u32::<BigEndian>().unwrap()),
				ChildNumber::from(rdr.read_u32::<BigEndian>().unwrap()),
			],
		}
	}

	/// to an Identifier [manual serialization]
	pub fn to_identifier(&self) -> Identifier {
		let mut wtr = vec![];
		wtr.write_u8(self.depth).unwrap();
		wtr.write_u32::<BigEndian>(<u32>::from(self.path[0]))
			.unwrap();
		wtr.write_u32::<BigEndian>(<u32>::from(self.path[1]))
			.unwrap();
		wtr.write_u32::<BigEndian>(<u32>::from(self.path[2]))
			.unwrap();
		wtr.write_u32::<BigEndian>(<u32>::from(self.path[3]))
			.unwrap();
		let mut retval = [0u8; IDENTIFIER_SIZE];
		retval.copy_from_slice(&wtr[0..IDENTIFIER_SIZE]);
		Identifier(retval)
	}

	/// Return path as the &[ChildNumber]
	pub fn as_ref(&self) -> &[ChildNumber] {
		&self.path[0..self.depth as usize]
	}

	/// Last part of the path (for last n_child)
	pub fn last_path_index(&self) -> u32 {
		if self.depth == 0 {
			0
		} else {
			<u32>::from(self.path[self.depth as usize - 1])
		}
	}

	/// Extend chain path with a given derivation index
	pub fn extend(&self, d: u32) -> ExtKeychainPath {
		let mut extended_path = self.clone();
		let new_depth = min(4, extended_path.depth + 1);
		extended_path.depth = new_depth;
		extended_path.path[new_depth as usize - 1] = ChildNumber::from(d);
		extended_path
	}
}

/// Wrapper for public amount + w + path
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ValueExtKeychainPath {
	pub value: u64,
	pub w: i64,
	pub ext_keychain_path: ExtKeychainPath,
}

pub trait Keychain: Sync + Send + Clone {
	/// Generates a keychain from a raw binary seed (which has already been
	/// decrypted if applicable).
	fn from_seed(seed: &[u8], is_floo: bool) -> Result<Self, Error>;

	/// Generates a keychain from a list of space-separated mnemonic words
	fn from_mnemonic(word_list: &str, extension_word: &str, is_floo: bool) -> Result<Self, Error>;

	/// Generates a keychain from a randomly generated seed. Mostly used for tests.
	fn from_random_seed(is_floo: bool) -> Result<Self, Error>;

	/// Root identifier for that keychain
	fn root_key_id() -> Identifier;

	/// Derives a key id from the depth of the keychain and the values at each
	/// depth level. See `KeychainPath` for more information.
	fn derive_key_id(depth: u8, d1: u32, d2: u32, d3: u32, d4: u32) -> Identifier;

	/// The public root key
	fn public_root_key(&self) -> PublicKey;

	fn derive_key(&self, id: &Identifier) -> Result<SecretKey, Error>;
	fn derive_pub_key(&self, id: &Identifier) -> Result<PublicKey, Error>;
	fn search_pub_key(
		&self,
		d0_until: u32,
		d1_until: u32,
		dest_pub_key: &PublicKey,
	) -> Result<Identifier, Error>;
	fn commit(&self, w: i64, id: &Identifier) -> Result<Commitment, Error>;
	fn commit_raw(&self, w: i64, key: &SecretKey) -> Result<Commitment, Error>;
	fn blind_sum(&self, blind_sum: &BlindSum) -> Result<BlindingFactor, Error>;
	fn rewind_nonce(&self, commit: &Commitment) -> Result<SecretKey, Error>;

	/// ECDSA Signature.
	/// Note: only used for test. For production, we use Schnorr Signature instead.
	fn sign(&self, msg: &Message, id: &Identifier) -> Result<Signature, Error>;

	/// ECDSA Signature.
	/// Note: only used for test. For production, we use Schnorr Signature instead.
	fn sign_with_blinding(&self, _: &Message, _: &BlindingFactor) -> Result<Signature, Error>;

	fn secp(&self) -> &Secp256k1;
}

#[cfg(test)]
mod test {
	use rand::thread_rng;

	use crate::types::{BlindingFactor, ExtKeychainPath, Identifier};
	use crate::util::secp::constants::SECRET_KEY_SIZE;
	use crate::util::secp::key::{SecretKey, ZERO_KEY};
	use crate::util::secp::Secp256k1;
	use std::slice::from_raw_parts;

	// This tests cleaning of BlindingFactor (e.g. secret key) on Drop.
	// To make this test fail, just remove `Zeroize` derive from `BlindingFactor` definition.
	#[test]
	fn blinding_factor_clear_on_drop() {
		// Create buffer for blinding factor filled with non-zero bytes.
		let bf_bytes = [0xAA; SECRET_KEY_SIZE];
		let ptr = {
			// Fill blinding factor with some "sensitive" data
			let bf = BlindingFactor::from_slice(&bf_bytes[..]);
			bf.0.as_ptr()

			// -- after this line BlindingFactor should be zeroed
		};

		// Unsafely get data from where BlindingFactor was in memory. Should be all zeros.
		let bf_bytes = unsafe { from_raw_parts(ptr, SECRET_KEY_SIZE) };

		// There should be all zeroes.
		let mut all_zeros = true;
		for b in bf_bytes {
			if *b != 0x00 {
				all_zeros = false;
			}
		}

		assert!(all_zeros)
	}

	#[test]
	fn split_blinding_factor() {
		let secp = Secp256k1::new();
		let skey_in = SecretKey::new(&mut thread_rng());
		let blind = BlindingFactor::from_secret_key(skey_in.clone());
		let split = blind.split(&secp).unwrap();

		// split a key, sum the split keys and confirm the sum matches the original key
		let mut skey_sum = split.blind_1.secret_key().unwrap();
		let skey_2 = split.blind_2.secret_key().unwrap();
		let _ = skey_sum.add_assign(&skey_2).unwrap();
		assert_eq!(skey_in, skey_sum);
	}

	// Sanity check that we can add the zero key to a secret key and it is still
	// the same key that we started with (k + 0 = k)
	#[test]
	fn zero_key_addition() {
		let skey_in = SecretKey::new(&mut thread_rng());
		let skey_zero = ZERO_KEY;

		let mut skey_out = skey_in.clone();
		let _ = skey_out.add_assign(&skey_zero).unwrap();

		assert_eq!(skey_in, skey_out);
	}

	// Check path identifiers
	#[test]
	fn path_identifier() {
		let path = ExtKeychainPath::new(4, 1, 2, 3, 4);
		let id = Identifier::from_path(&path);
		println!("id.to_bip_32_string = {}", id.to_bip_32_string());
		let ret_path = id.to_path();
		assert_eq!(path, ret_path);

		let path = ExtKeychainPath::new(
			1,
			<u32>::max_value(),
			<u32>::max_value(),
			3,
			<u32>::max_value(),
		);
		let id = Identifier::from_path(&path);
		let ret_path = id.to_path();
		assert_eq!(path, ret_path);

		assert_eq!(
			format!("{:02x?}", path.as_ref()),
			"[Hardened { index: 7fffffff }]"
		);
		println!("id: {:?}", id);
		println!("ret_path {:?}", ret_path);

		let path = ExtKeychainPath::new(0, 0, 0, 0, 0);
		assert_eq!(format!("{:02x?}", path.as_ref()), "[]");
		let path = ExtKeychainPath::new(4, 1, 2, 3, 4);
		assert_eq!(format!("{:02x?}", path.as_ref()), "[Normal { index: 01 }, Normal { index: 02 }, Normal { index: 03 }, Normal { index: 04 }]");

		let path = ExtKeychainPath::new(3, 0, 0, 10, 0);
		let id = Identifier::from_path(&path);
		let parent_id = id.parent_path();
		let expected_path = ExtKeychainPath::new(2, 0, 0, 0, 0);
		let expected_id = Identifier::from_path(&expected_path);
		assert_eq!(expected_id, parent_id);
	}
}
