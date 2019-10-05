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

//! Rangeproof library functions

use super::secp_ser::pubkey_serde;
use crate::address::Address;
use crate::blake2::blake2b::blake2b;
use crate::core::hash::{Hash, Hashed};
use crate::keychain::{Identifier, Keychain};
use crate::libtx::error::{Error, ErrorKind};
use crate::ser::{self, Readable, Reader, Writeable, Writer};
use crate::util;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::util::secp::{self, Secp256k1};
use crate::zeroize::Zeroize;

use bitcoin_hashes::{self, hash160};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::thread_rng;
use std::cmp::min;
use std::io::Cursor;

/// size of the reserved zero prefix in SecuredPath
pub const SECURED_PATH_PREFIX_SIZE: usize = 3;
/// Size of a SecuredPath in bytes.
pub const SECURED_PATH_SIZE: usize = SECURED_PATH_PREFIX_SIZE + 8 + 17;
/// Size of an OutputLocker in bytes.
pub const OUTPUT_LOCKER_SIZE: usize = 32 + secp::COMPRESSED_PUBLIC_KEY_SIZE + 8 + 4;

/// A locker to limit an output only spendable to someone who owns the private key of 'p2pkh'.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputLocker {
	/// The hash160 hash of 'Pay-to-Public-Key-Hash'.
	pub p2pkh: hash160::Hash,
	/// The 'R' for ephemeral key: `q = Hash(secured_w || p*R)`.
	#[serde(with = "pubkey_serde")]
	pub pub_nonce: PublicKey,
	/// The secured version of 'w' for the Pedersen commitment: `C = q*G + w*H`,
	/// the real 'w' can be calculated by: `w = secured_w XOR q[0..8]`.
	pub secured_w: i64,
	/// The relative lock height, after which the output can be spent.
	pub relative_lock_height: u32,
}

impl Writeable for OutputLocker {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.p2pkh.write(writer)?;
		self.pub_nonce.write(writer)?;
		writer.write_i64(self.secured_w)?;
		writer.write_u32(self.relative_lock_height)?;
		Ok(())
	}
}

impl Readable for OutputLocker {
	fn read(reader: &mut dyn Reader) -> Result<OutputLocker, ser::Error> {
		let p2pkh = hash160::Hash::read(reader)?;
		let pub_nonce = PublicKey::read(reader)?;
		let secured_w = reader.read_i64()?;
		let relative_lock_height = reader.read_u32()?;
		Ok(OutputLocker {
			p2pkh,
			pub_nonce,
			secured_w,
			relative_lock_height,
		})
	}
}

/// Create a OutputLocker
pub fn create_output_locker<K>(
	k: &K,
	recipient_pubkey: &PublicKey,
	secured_w: i64,
	relative_lock_height: u32,
	key_id: &Identifier,
) -> Result<(Commitment, OutputLocker), Error>
where
	K: Keychain,
{
	let secp = k.secp();
	let private_nonce = SecretKey::new(&secp, &mut thread_rng());
	let pub_nonce = PublicKey::from_secret_key(&secp, &private_nonce)?;

	// The ephemeral key: `q = Hash(secured_w || k*P)`
	let mut tmp = recipient_pubkey.clone();
	tmp.mul_assign(&secp, &private_nonce)?;
	let hash = (secured_w, tmp).hash();
	let ephemeral_key_q = SecretKey::from_slice(&secp, hash.as_bytes())?;

	// The real 'w' is calculated by: `w = secured_w XOR q[0..8]`.
	let mut buf = &ephemeral_key_q.0[0..8];
	let num = buf.read_i64::<LittleEndian>().unwrap();
	let w = secured_w ^ num;

	// The Pedersen commitment: `C = q*G + w*H`.
	let commit = k.commit(w, key_id)?;

	Ok((
		commit,
		OutputLocker {
			p2pkh: Address::pkh(recipient_pubkey),
			pub_nonce,
			secured_w,
			relative_lock_height,
		},
	))
}

/// A secured path message which hide the key identifier and the random w of commitment
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecuredPath(pub [u8; SECURED_PATH_SIZE]);

impl AsRef<[u8]> for SecuredPath {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}

impl SecuredPath {
	/// Create a SecuredPath from a vector
	pub fn from_vec(v: Vec<u8>) -> SecuredPath {
		SecuredPath::from_slice(&v)
	}

	/// Create a SecuredPath from a slice
	pub fn from_slice(data: &[u8]) -> SecuredPath {
		let mut bin = [0; SECURED_PATH_SIZE];
		match data.len() {
			SECURED_PATH_SIZE => bin[..].copy_from_slice(data),
			len => {
				for i in 0..min(SECURED_PATH_SIZE, len) {
					bin[i] = data[i];
				}
			}
		}
		SecuredPath(bin)
	}

	/// Get the hex string from a SecuredPath
	pub fn to_hex(&self) -> String {
		util::to_hex(self.0.to_vec())
	}

	/// Create a SecuredPath from a hex string
	pub fn from_hex(hex: &str) -> Result<SecuredPath, Error> {
		let bytes =
			util::from_hex(hex.to_string()).map_err(|e| ErrorKind::PathMessage(e.to_string()))?;
		Ok(SecuredPath::from_slice(&bytes))
	}

	/// Create a SecuredPath from the PathMessage
	pub fn from_path(path_msg: &PathMessage, none: &Hash) -> SecuredPath {
		let mut bin = [0; SECURED_PATH_SIZE];
		bin[0..SECURED_PATH_PREFIX_SIZE].copy_from_slice(&path_msg.reserved);
		let mut wtr = vec![];
		wtr.write_i64::<LittleEndian>(path_msg.w).unwrap();
		bin[SECURED_PATH_PREFIX_SIZE..SECURED_PATH_PREFIX_SIZE + 8].copy_from_slice(&wtr);
		bin[SECURED_PATH_PREFIX_SIZE + 8..].copy_from_slice(path_msg.key_id.as_ref());
		let encoded: Vec<u8> = bin
			.iter()
			.zip(none.to_vec().iter())
			.map(|(a, b)| *a ^ *b)
			.collect();
		SecuredPath::from_slice(&encoded)
	}

	/// Get the hidden PathMessage from a SecuredPath
	pub fn get_path(&self, none: &Hash) -> Result<PathMessage, Error> {
		let decoded: Vec<u8> = self
			.0
			.iter()
			.zip(none.to_vec().iter())
			.map(|(a, b)| *a ^ *b)
			.collect();
		PathMessage::from_slice(&decoded)
	}
}

/// The key derivation path and the random w of commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMessage {
	/// Reserved at this moment.
	pub reserved: [u8; SECURED_PATH_PREFIX_SIZE],
	/// The random 'w' of Pedersen commitment `r*G + w*H`
	pub w: i64,
	/// The key identifier
	pub key_id: Identifier,
}

impl PathMessage {
	/// Create a PathMessage from a slice
	pub fn from_slice(data: &[u8]) -> Result<PathMessage, Error> {
		if data.len() != SECURED_PATH_SIZE {
			return Err(ErrorKind::PathMessage("wrong path message".to_owned()).into());
		}
		let mut reserved = [0u8; SECURED_PATH_PREFIX_SIZE];
		reserved.copy_from_slice(&data[0..SECURED_PATH_PREFIX_SIZE]);

		if reserved.iter().fold(0u32, |acc, x| acc + *x as u32) != 0 {
			return Err(ErrorKind::PathMessage("wrong path message".to_owned()).into());
		}

		let mut rdr =
			Cursor::new((&data[SECURED_PATH_PREFIX_SIZE..SECURED_PATH_PREFIX_SIZE + 8]).clone());
		let w = rdr.read_i64::<LittleEndian>().unwrap();;
		let key_id: Identifier = Identifier::from_bytes(&data[SECURED_PATH_PREFIX_SIZE + 8..]);

		Ok(PathMessage {
			reserved,
			w,
			key_id,
		})
	}
}

/// Create a SecuredPath
pub fn create_secured_path<K, B>(
	k: &K,
	b: &B,
	w: i64,
	key_id: &Identifier,
	commit: Commitment,
) -> SecuredPath
where
	K: Keychain,
	B: ProofBuild,
{
	let secp = k.secp();
	let rewind_nonce = b.rewind_nonce(secp, &commit);
	let message = b.proof_message(secp, w, key_id);
	SecuredPath::from_path(&message, &rewind_nonce)
}

/// Rewind a SecuredPath to retrieve the PathMessage
pub fn rewind<B>(
	secp: &Secp256k1,
	b: &B,
	commit: &Commitment,
	spath: &SecuredPath,
) -> Result<PathMessage, Error>
where
	B: ProofBuild,
{
	let nonce = b.rewind_nonce(secp, commit);
	let info = spath.get_path(&nonce)?;

	let _key_id = b
		.check_output(secp, commit, &info)
		.map_err(|e| ErrorKind::PathMessage(e.to_string()))?;

	Ok(info)
}

/// Used for building SecuredPath and checking if the output belongs to the wallet
pub trait ProofBuild: Sync + Send + Clone {
	/// Create a nonce that will allow to rewind the derivation path and flags
	fn rewind_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Hash;

	/// Create a PathMessage
	fn proof_message(&self, secp: &Secp256k1, w: i64, id: &Identifier) -> PathMessage;

	/// Check if the output belongs to this keychain
	fn check_output(
		&self,
		secp: &Secp256k1,
		commit: &Commitment,
		message: &PathMessage,
	) -> Result<Identifier, Error>;
}

/// The proof builder
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProofBuilder<'a, K>
where
	K: Keychain,
{
	/// Keychain
	keychain: &'a K,
	/// Hash(root_pub_key)
	rewind_hash: Hash,
}

impl<'a, K> ProofBuilder<'a, K>
where
	K: Keychain,
{
	/// Creates a new instance of this proof builder
	pub fn new(keychain: &'a K) -> Self {
		let public_root_key = keychain
			.public_root_key()
			.serialize_vec(keychain.secp(), true);
		let rewind_hash = Hash::from_vec(blake2b(32, &[], &public_root_key[..]).as_bytes());

		Self {
			keychain,
			rewind_hash,
		}
	}

	fn nonce(&self, commit: &Commitment) -> Hash {
		Hash::from_vec(blake2b(32, &commit.0, self.rewind_hash.as_bytes()).as_bytes())
	}
}

impl<'a, K> ProofBuild for ProofBuilder<'a, K>
where
	K: Keychain,
{
	fn rewind_nonce(&self, _secp: &Secp256k1, commit: &Commitment) -> Hash {
		self.nonce(commit)
	}

	fn proof_message(&self, _secp: &Secp256k1, w: i64, id: &Identifier) -> PathMessage {
		PathMessage {
			reserved: [0u8; SECURED_PATH_PREFIX_SIZE],
			w,
			key_id: id.clone(),
		}
	}

	fn check_output(
		&self,
		_secp: &Secp256k1,
		commit: &Commitment,
		message: &PathMessage,
	) -> Result<Identifier, Error> {
		let commit_exp = self.keychain.commit(message.w, &message.key_id)?;
		match commit == &commit_exp {
			true => Ok(message.key_id.clone()),
			false => Err(ErrorKind::PathMessage("check NOK".to_owned()).into()),
		}
	}
}

impl<'a, K> Zeroize for ProofBuilder<'a, K>
where
	K: Keychain,
{
	fn zeroize(&mut self) {
		self.rewind_hash.zeroize();
	}
}

impl<'a, K> Drop for ProofBuilder<'a, K>
where
	K: Keychain,
{
	fn drop(&mut self) {
		self.zeroize();
	}
}
