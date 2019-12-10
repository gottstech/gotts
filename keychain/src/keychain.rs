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

/// Implementation of the Keychain trait based on an extended key derivation
/// scheme.
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use crate::blake2::blake2b::blake2b;

use crate::extkey_bip32::{BIP32GottsHasher, ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use crate::types::{BlindSum, BlindingFactor, Error, ExtKeychainPath, Identifier, Keychain};
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::util::secp::{self, Message, Secp256k1, Signature};

/// Key as a recipient
#[derive(Clone, Debug)]
pub struct RecipientKey {
	/// As recipient of non-interactive transaction, the key derivation path of the public address.
	pub recipient_key_id: Identifier,
	/// The public key of the recipient public address
	pub recipient_pub_key: PublicKey,
	/// The private key of the recipient public address
	pub recipient_pri_key: SecretKey,
}

/// Extended Keychain
#[derive(Clone, Debug)]
pub struct ExtKeychain {
	/// The secp256k1 engine, used to execute all signature operations
	secp: Secp256k1,
	/// Master Key
	master: ExtendedPrivKey,
	/// BIP32 Hasher
	hasher: BIP32GottsHasher,
}

impl Keychain for ExtKeychain {
	fn from_seed(seed: &[u8], is_floo: bool) -> Result<Self, Error> {
		let mut h = BIP32GottsHasher::new(is_floo);
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);
		let master = ExtendedPrivKey::new_master(&mut h, seed)?;

		let keychain = ExtKeychain {
			secp,
			master,
			hasher: h,
		};
		Ok(keychain)
	}

	fn from_mnemonic(word_list: &str, extension_word: &str, is_floo: bool) -> Result<Self, Error> {
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);
		let h = BIP32GottsHasher::new(is_floo);
		let master = ExtendedPrivKey::from_mnemonic(word_list, extension_word, is_floo)?;

		let keychain = ExtKeychain {
			secp,
			master,
			hasher: h,
		};
		Ok(keychain)
	}

	/// For testing - probably not a good idea to use outside of tests.
	fn from_random_seed(is_floo: bool) -> Result<Self, Error> {
		let seed: String = thread_rng().sample_iter(&Alphanumeric).take(16).collect();
		let seed = blake2b(32, &[], seed.as_bytes());
		ExtKeychain::from_seed(seed.as_bytes(), is_floo)
	}

	fn root_key_id() -> Identifier {
		ExtKeychainPath::new(0, 0, 0, 0, 0).to_identifier()
	}

	fn derive_key_id(depth: u8, d1: u32, d2: u32, d3: u32, d4: u32) -> Identifier {
		ExtKeychainPath::new(depth, d1, d2, d3, d4).to_identifier()
	}

	fn public_root_key(&self) -> PublicKey {
		PublicKey::from_secret_key(&self.secp, &self.master.secret_key).unwrap()
	}

	fn derive_key(&self, id: &Identifier) -> Result<SecretKey, Error> {
		let mut h = self.hasher.clone();
		Ok(self
			.master
			.derive_priv(&self.secp, &mut h, id.to_path().as_ref())?
			.secret_key)
	}

	fn derive_pub_key(&self, id: &Identifier) -> Result<PublicKey, Error> {
		Ok(PublicKey::from_secret_key(
			&self.secp,
			&self.derive_key(id)?,
		)?)
	}

	fn search_pub_key(
		&self,
		d0_until: u32,
		d1_until: u32,
		last_path: u32,
		dest_pub_key: &PublicKey,
	) -> Result<Identifier, Error> {
		let secp = self.secp();
		let mut hasher = self.hasher.clone();
		let pk = ExtendedPubKey::from_private(secp, &self.master, &mut hasher);
		let last_child_number = ChildNumber::from(last_path);
		for d0 in 0..d0_until {
			let pk0 = pk.ckd_pub(secp, &mut hasher, ChildNumber::from(d0))?;
			for d1 in 0..d1_until {
				let pk1 = pk0.ckd_pub(secp, &mut hasher, ChildNumber::from(d1))?;
				let pk2 = pk1.ckd_pub(secp, &mut hasher, last_child_number)?;
				if pk2.public_key == *dest_pub_key {
					let key_id = ExtKeychainPath::new(2, d0, d1, 0, 0).to_identifier();
					return Ok(key_id);
				}
			}
		}
		Err(Error::Generic("not found".to_string()))
	}

	fn commit(&self, w: i64, id: &Identifier) -> Result<Commitment, Error> {
		let key = self.derive_key(id)?;
		let commit = self.secp.commit_i(w, &key)?;
		Ok(commit)
	}

	fn commit_raw(&self, w: i64, key: &SecretKey) -> Result<Commitment, Error> {
		let commit = self.secp.commit_i(w, key)?;
		Ok(commit)
	}

	fn blind_sum(&self, blind_sum: &BlindSum) -> Result<BlindingFactor, Error> {
		let mut pos_keys: Vec<SecretKey> = blind_sum
			.positive_key_ids
			.iter()
			.filter_map(|k| {
				let res = self.derive_key(&Identifier::from_path(&k.ext_keychain_path));
				if let Ok(s) = res {
					Some(s)
				} else {
					None
				}
			})
			.collect();

		let mut neg_keys: Vec<SecretKey> = blind_sum
			.negative_key_ids
			.iter()
			.filter_map(|k| {
				let res = self.derive_key(&Identifier::from_path(&k.ext_keychain_path));
				if let Ok(s) = res {
					Some(s)
				} else {
					None
				}
			})
			.collect();

		let keys = blind_sum
			.positive_blinding_factors
			.iter()
			.filter_map(|b| b.secret_key().ok().clone())
			.collect::<Vec<SecretKey>>();
		pos_keys.extend(keys);

		let keys = blind_sum
			.negative_blinding_factors
			.iter()
			.filter_map(|b| b.secret_key().ok().clone())
			.collect::<Vec<SecretKey>>();
		neg_keys.extend(keys);

		let sum = self.secp.blind_sum(pos_keys, neg_keys)?;
		Ok(BlindingFactor::from_secret_key(sum))
	}

	fn rewind_nonce(&self, commit: &Commitment) -> Result<SecretKey, Error> {
		// hash(commit|wallet root secret key (m)) as nonce
		let root_key = self.derive_key(&Self::root_key_id())?;
		let res = blake2b(32, &commit.0, &root_key.0[..]);
		let res = res.as_bytes();
		SecretKey::from_slice(&res)
			.map_err(|e| Error::RangeProof(format!("Unable to create nonce: {:?}", e).to_string()))
	}

	/// ECDSA Signature.
	/// Note: only used for test. For production, we use Schnorr Signature instead.
	fn sign(&self, msg: &Message, id: &Identifier) -> Result<Signature, Error> {
		let skey = self.derive_key(id)?;
		let sig = self.secp.sign(msg, &skey)?;
		Ok(sig)
	}

	/// ECDSA Signature.
	/// Note: only used for test. For production, we use Schnorr Signature instead.
	fn sign_with_blinding(
		&self,
		msg: &Message,
		blinding: &BlindingFactor,
	) -> Result<Signature, Error> {
		let skey = &blinding.secret_key()?;
		let sig = self.secp.sign(msg, &skey)?;
		Ok(sig)
	}

	fn secp(&self) -> &Secp256k1 {
		&self.secp
	}
}

#[cfg(test)]
mod test {
	use crate::keychain::ExtKeychain;
	use crate::types::{BlindSum, BlindingFactor, ExtKeychainPath, Keychain};
	use crate::util::secp;
	use crate::util::secp::key::{PublicKey, SecretKey};

	#[test]
	fn test_key_derivation() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let secp = keychain.secp();

		let path = ExtKeychainPath::new(4, 1, 0, 0, 0);
		let key_id = path.to_identifier();
		println!("key_id.to_bip_32_string = {}", key_id.to_bip_32_string());

		let msg_bytes = [0; 32];
		let msg = secp::Message::from_slice(&msg_bytes[..]).unwrap();

		// now create a zero commitment using the key on the keychain associated with
		// the key_id
		let commit = keychain.commit(0, &key_id).unwrap();

		// now check we can use our key to verify a signature from this zero commitment
		let sig = keychain.sign(&msg, &key_id).unwrap();
		secp.verify_from_commit(&msg, &sig, &commit).unwrap();

		// check derive_key and derive_pub_key
		let key_id = ExtKeychain::derive_key_id(4, 5, 5, 0, 0);
		let prikey = keychain.derive_key(&key_id).unwrap();
		let pubkey = PublicKey::from_secret_key(keychain.secp(), &prikey).unwrap();
		assert_eq!(pubkey, keychain.derive_pub_key(&key_id).unwrap());
		// use them for ECDSA Signature
		let sig = keychain.sign(&msg, &key_id).unwrap();
		assert_eq!(secp.verify(&msg, &sig, &pubkey).is_ok(), true);
		// use them for Schnorr Signature
		let sig =
			secp::aggsig::sign_single(&secp, &msg, &prikey, None, None, None, Some(&pubkey), None)
				.unwrap();
		assert_eq!(
			secp::aggsig::verify_single(
				&secp,
				&sig,
				&msg,
				None,
				&pubkey,
				Some(&pubkey),
				None,
				false,
			),
			true
		);

		// exception cases
		let key_id = ExtKeychain::derive_key_id(0, 0, 0, 0, 0);
		let prikey = keychain.derive_key(&key_id).unwrap();
		assert_eq!(prikey, keychain.master.secret_key);
		let pubkey = PublicKey::from_secret_key(keychain.secp(), &prikey).unwrap();
		assert_eq!(pubkey, keychain.derive_pub_key(&key_id).unwrap());
	}

	// We plan to "offset" the key used in the kernel commitment
	// so we are going to be doing some key addition/subtraction.
	// This test is mainly to demonstrate that idea that summing commitments
	// and summing the keys used to commit to 0 have the same result.
	#[test]
	fn secret_key_addition() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();

		let skey1 = SecretKey::from_slice(&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 1,
		])
		.unwrap();

		let skey2 = SecretKey::from_slice(&[
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 2,
		])
		.unwrap();

		// adding secret keys 1 and 2 to give secret key 3
		let mut skey3 = skey1.clone();
		let _ = skey3.add_assign(&skey2).unwrap();

		// create commitments for secret keys 1, 2 and 3
		// all committing to the value 0 (which is what we do for tx_kernels)
		let commit_1 = keychain.secp.commit_i(0i64, &skey1).unwrap();
		let commit_2 = keychain.secp.commit_i(0i64, &skey2).unwrap();
		let commit_3 = keychain.secp.commit_i(0i64, &skey3).unwrap();

		// now sum commitments for keys 1 and 2
		let sum = keychain
			.secp
			.commit_sum(vec![commit_1.clone(), commit_2.clone()], vec![])
			.unwrap();

		// confirm the commitment for key 3 matches the sum of the commitments 1 and 2
		assert_eq!(sum, commit_3);

		// now check we can sum keys up using keychain.blind_sum()
		// in the same way (convenience function)
		assert_eq!(
			keychain
				.blind_sum(
					&BlindSum::new()
						.add_blinding_factor(BlindingFactor::from_secret_key(skey1))
						.add_blinding_factor(BlindingFactor::from_secret_key(skey2))
				)
				.unwrap(),
			BlindingFactor::from_secret_key(skey3),
		);
	}
}
