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
use crate::blake2::blake2b::blake2b;
use crate::core::hash::{Hash, Hashed};
use crate::keychain::{Identifier, Keychain};
use crate::libtx::error::{Error, ErrorKind};
use crate::libtx::secp_ser;
use crate::ser::{self, Readable, Reader, Writeable, Writer};
use crate::util;
use crate::util::secp;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::zeroize::Zeroize;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::thread_rng;
use std::cmp::min;
use std::io::Cursor;

/// Size of a SecuredPath in bytes.
pub const SECURED_PATH_SIZE: usize = 8 + 4;
/// Size of an OutputLocker in bytes.
pub const OUTPUT_LOCKER_SIZE: usize = 32 + secp::COMPRESSED_PUBLIC_KEY_SIZE + 8 + 4;

/// A locker to limit an output only spendable to someone who owns the private key of 'p2pkh'.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputLocker {
	/// The Blake2b hash of 'Pay-to-Public-Key-Hash'.
	pub p2pkh: Hash,
	/// The 'R' for ephemeral key: `q = Hash(secured_w || p*R)`.
	#[serde(with = "pubkey_serde")]
	pub pub_nonce: PublicKey,
	/// A secured path message which hide the key derivation path and the random w of commitment.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::securedpath_from_hex"
	)]
	pub spath: SecuredPath,
}

impl OutputLocker {
	/// Get the ephemeral key: `q = Hash(value || p*R)`, for self owned output
	pub fn get_ephemeral_key<K>(
		&self,
		k: &K,
		value: u64,
		recipient_prikey: &SecretKey,
	) -> Result<SecretKey, Error>
	where
		K: Keychain,
	{
		let secp = k.secp();
		let mut tmp = self.pub_nonce.clone();
		tmp.mul_assign(&secp, recipient_prikey)?;
		let hash = (value, tmp.serialize_vec(true)).hash();
		let ephemeral_key_q = SecretKey::from_slice(hash.as_bytes())?;
		Ok(ephemeral_key_q)
	}
}

impl Writeable for OutputLocker {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.p2pkh.write(writer)?;
		self.pub_nonce.write(writer)?;
		self.spath.write(writer)?;
		Ok(())
	}
}

impl Readable for OutputLocker {
	fn read(reader: &mut dyn Reader) -> Result<OutputLocker, ser::Error> {
		let p2pkh = Hash::read(reader)?;
		let pub_nonce = PublicKey::read(reader)?;
		let spath = SecuredPath::read(reader)?;
		Ok(OutputLocker {
			p2pkh,
			pub_nonce,
			spath,
		})
	}
}

/// Create a OutputLocker
pub fn create_output_locker<K>(
	k: &K,
	value: u64,
	recipient_pubkey: &PublicKey,
	w: i64,
	key_id_last_path: u32,
	use_test_rng: bool,
) -> Result<(Commitment, OutputLocker, SecretKey), Error>
where
	K: Keychain,
{
	let secp = k.secp();
	let private_nonce = if !use_test_rng {
		SecretKey::new(&mut thread_rng())
	} else {
		SecretKey::from_slice(&[1; 32]).unwrap()
	};
	let pub_nonce = PublicKey::from_secret_key(&secp, &private_nonce)?;

	// The ephemeral key: `q = Hash(value || k*P)`
	let mut tmp = recipient_pubkey.clone();
	tmp.mul_assign(&secp, &private_nonce)?;
	let hash = (value, tmp.serialize_vec(true)).hash();
	let ephemeral_key_q = SecretKey::from_slice(hash.as_bytes())?;

	// The spath is calculated by: `spath = PathMessage XOR Hash(q)`.
	let rewind_nonce = ephemeral_key_q.0.to_vec().hash();
	let message = PathMessage {
		w,
		key_id_last_path,
	};
	let spath = SecuredPath::from_path(&message, &rewind_nonce);

	// The Pedersen commitment: `C = q*G + w*H`.
	let commit = k.commit_raw(w, &ephemeral_key_q)?;

	Ok((
		commit,
		OutputLocker {
			p2pkh: recipient_pubkey.serialize_vec(true).hash(),
			pub_nonce,
			spath,
		},
		ephemeral_key_q,
	))
}

/// Rewind a OutputLocker to retrieve the 'w'
pub fn rewind_outputlocker<K>(
	k: &K,
	value: u64,
	recipient_prikey: &SecretKey,
	commit: &Commitment,
	locker: &OutputLocker,
) -> Result<(PathMessage, SecretKey), Error>
where
	K: Keychain,
{
	// The ephemeral key: `q = Hash(value || p*R)`
	let ephemeral_key_q = locker.get_ephemeral_key(k, value, recipient_prikey)?;

	// The spath is calculated by: `spath = PathMessage XOR Hash(q)`.
	let rewind_nonce = ephemeral_key_q.0.to_vec().hash();
	let info = locker.spath.get_path(&rewind_nonce);

	// Check output
	let commit_exp = k.commit_raw(info.w, &ephemeral_key_q)?;
	match commit == &commit_exp {
		true => Ok((info, ephemeral_key_q)),
		false => Err(ErrorKind::OutputLocker("check NOK".to_owned()).into()),
	}
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
		let mut bin = vec![];
		bin.write_i64::<LittleEndian>(path_msg.w).unwrap();
		bin.write_u32::<LittleEndian>(path_msg.key_id_last_path)
			.unwrap();
		let encoded: Vec<u8> = bin
			.iter()
			.zip(none.to_vec().iter())
			.map(|(a, b)| *a ^ *b)
			.collect();
		SecuredPath::from_slice(&encoded)
	}

	/// Get the hidden PathMessage from a SecuredPath
	pub fn get_path(&self, none: &Hash) -> PathMessage {
		let decoded: Vec<u8> = self
			.0
			.iter()
			.zip(none.to_vec().iter())
			.map(|(a, b)| *a ^ *b)
			.collect();
		PathMessage::from_slice(&decoded).unwrap()
	}
}

/// The key derivation path and the random w of commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMessage {
	/// The random 'w' of Pedersen commitment `r*G + w*H`
	pub w: i64,
	/// The last path index of the key identifier
	pub key_id_last_path: u32,
}

impl PathMessage {
	/// Create a PathMessage from a slice
	pub fn from_slice(data: &[u8]) -> Result<PathMessage, Error> {
		if data.len() != SECURED_PATH_SIZE {
			return Err(ErrorKind::PathMessage("wrong path message".to_owned()).into());
		}

		let mut rdr = Cursor::new((&data[0..8]).clone());
		let w = rdr.read_i64::<LittleEndian>().unwrap();
		let mut rdr = Cursor::new((&data[8..]).clone());
		let key_id_last_path = rdr.read_u32::<LittleEndian>().unwrap();

		Ok(PathMessage {
			w,
			key_id_last_path,
		})
	}

	/// Create a PathMessage from w and id
	pub fn create(w: i64, id: &Identifier) -> PathMessage {
		PathMessage {
			w,
			key_id_last_path: id.to_path().last_path_index(),
		}
	}
}

/// Create a SecuredPath
pub fn create_secured_path<B>(b: &B, w: i64, key_id: &Identifier, commit: Commitment) -> SecuredPath
where
	B: ProofBuild,
{
	let rewind_nonce = b.rewind_nonce(&commit);
	let message = PathMessage::create(w, key_id);
	SecuredPath::from_path(&message, &rewind_nonce)
}

/// Rewind a SecuredPath to retrieve the PathMessage
pub fn rewind<B>(
	b: &B,
	active_key_id: &Identifier,
	commit: &Commitment,
	spath: &SecuredPath,
) -> Result<PathMessage, Error>
where
	B: ProofBuild,
{
	let nonce = b.rewind_nonce(commit);
	let info = spath.get_path(&nonce);

	let _key_id = b
		.check_output(active_key_id, commit, &info)
		.map_err(|e| ErrorKind::PathMessage(e.to_string()))?;

	Ok(info)
}

/// Used for building SecuredPath and checking if the output belongs to the wallet
pub trait ProofBuild: Sync + Send + Clone {
	/// Create a nonce that will allow to rewind the derivation path and flags
	fn rewind_nonce(&self, commit: &Commitment) -> Hash;

	/// Check if the output belongs to this keychain
	fn check_output(
		&self,
		active_key_id: &Identifier,
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
	pub fn new(keychain: &'a K, rewind_hash_key_id: &Identifier) -> Self {
		let public_root_key = keychain
			.derive_pub_key(rewind_hash_key_id)
			.unwrap()
			.serialize_vec(true);
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
	fn rewind_nonce(&self, commit: &Commitment) -> Hash {
		self.nonce(commit)
	}

	fn check_output(
		&self,
		active_key_id: &Identifier,
		commit: &Commitment,
		message: &PathMessage,
	) -> Result<Identifier, Error> {
		let key_id = active_key_id
			.to_path()
			.extend(message.key_id_last_path)
			.to_identifier();
		let commit_exp = self.keychain.commit(message.w, &key_id)?;
		match commit == &commit_exp {
			true => Ok(key_id),
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
