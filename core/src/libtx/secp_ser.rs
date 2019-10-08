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

//! Sane serialization & deserialization of cryptographic structs into hex

use super::proof::SecuredPath;
use crate::keychain::BlindingFactor;
use crate::serde::{Deserialize, Deserializer, Serializer};
use crate::util::to_hex;

pub use crate::util::secp::{
	hex_to_key, option_pubkey_serde, option_sig_serde, pubkey_serde, sig_serde, u8_to_hex,
};

/// Creates a SecuredPath from a hex string
pub fn securedpath_from_hex<'de, D>(deserializer: D) -> Result<SecuredPath, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::Error;
	String::deserialize(deserializer).and_then(|string| {
		SecuredPath::from_hex(&string).map_err(|err| Error::custom(err.to_string()))
	})
}

/// Creates a BlindingFactor from a hex string
pub fn blind_from_hex<'de, D>(deserializer: D) -> Result<BlindingFactor, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::Error;
	String::deserialize(deserializer).and_then(|string| {
		BlindingFactor::from_hex(&string).map_err(|err| Error::custom(err.to_string()))
	})
}

/// Serializes a byte string into hex
pub fn as_hex<T, S>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
	T: AsRef<[u8]>,
	S: Serializer,
{
	serializer.serialize_str(&to_hex(bytes.as_ref().to_vec()))
}

/// Used to ensure u64s are serialised in json
/// as strings by default, since it can't be guaranteed that consumers
/// will know what to do with u64 literals (e.g. Javascript). However,
/// fields using this tag can be deserialized from literals or strings.
/// From solutions on:
/// https://github.com/serde-rs/json/issues/329
pub mod string_or_u64 {
	use serde::{de, Deserializer, Serializer};
	use std::fmt;

	/// serialize into a string
	pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		serializer.collect_str(value)
	}

	/// deserialize from either literal or string
	pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = u64;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"a string containing digits or an int fitting into u64"
				)
			}
			fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
				Ok(v)
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				s.parse().map_err(de::Error::custom)
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

/// As above, for Options
pub mod opt_string_or_u64 {
	use serde::{de, Deserializer, Serializer};
	use std::fmt;

	/// serialize into string or none
	pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		match value {
			Some(v) => serializer.collect_str(v),
			None => serializer.serialize_none(),
		}
	}

	/// deser from 'null', literal or string
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = Option<u64>;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"null, a string containing digits or an int fitting into u64"
				)
			}
			fn visit_unit<E>(self) -> Result<Self::Value, E> {
				Ok(None)
			}
			fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
				Ok(Some(v))
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				let val: u64 = s.parse().map_err(de::Error::custom)?;
				Ok(Some(val))
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

/// As above, for i64
pub mod string_or_i64 {
	use serde::{de, Deserializer, Serializer};
	use std::fmt;

	/// serialize into a string
	pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		serializer.collect_str(value)
	}

	/// deserialize from either literal or string
	pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = i64;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"a string containing digits or an int fitting into u64"
				)
			}
			fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
				Ok(v)
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				s.parse().map_err(de::Error::custom)
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
	use super::*;
	use crate::libtx::aggsig;
	use crate::util::secp::key::{PublicKey, SecretKey};
	use crate::util::secp::{option_sig_serde, pubkey_serde, sig_serde};
	use crate::util::secp::{Message, Signature};
	use crate::util::static_secp_instance;

	use serde_json;

	use rand::{thread_rng, Rng};

	#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
	struct SerTest {
		#[serde(with = "pubkey_serde")]
		pub pub_key: PublicKey,
		#[serde(with = "option_sig_serde")]
		pub opt_sig: Option<Signature>,
		#[serde(with = "sig_serde")]
		pub sig: Signature,
		#[serde(with = "string_or_u64")]
		pub num: u64,
		#[serde(with = "opt_string_or_u64")]
		pub opt_num: Option<u64>,
	}

	impl SerTest {
		pub fn random() -> SerTest {
			let static_secp = static_secp_instance();
			let secp = static_secp.lock();
			let sk = SecretKey::new(&mut thread_rng());
			let mut msg = [0u8; 32];
			thread_rng().fill(&mut msg);
			let msg = Message::from_slice(&msg).unwrap();
			let sig = aggsig::sign_single(&secp, &msg, &sk, None, None).unwrap();
			SerTest {
				pub_key: PublicKey::from_secret_key(&secp, &sk).unwrap(),
				opt_sig: Some(sig.clone()),
				sig: sig.clone(),
				num: 30,
				opt_num: Some(33),
			}
		}
	}

	#[test]
	fn ser_secp_primitives() {
		for _ in 0..10 {
			let s = SerTest::random();
			println!("Before Serialization: {:?}", s);
			let serialized = serde_json::to_string_pretty(&s).unwrap();
			println!("JSON: {}", serialized);
			let deserialized: SerTest = serde_json::from_str(&serialized).unwrap();
			println!("After Serialization: {:?}", deserialized);
			println!();
			assert_eq!(s, deserialized);
		}
	}
}
