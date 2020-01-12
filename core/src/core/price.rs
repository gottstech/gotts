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

//! ExchangeRate and ExchangeRates

use chrono::{DateTime, Duration, NaiveDateTime, Timelike, Utc};
use itertools::Itertools;

use crate::consensus;
use crate::core::hash::Hashed;
use crate::libtx::secp_ser;
use crate::ser::{self, read_multi, Readable, Reader, Writeable, Writer};
use crate::util::secp::{self, Signature};
use crate::util::static_secp_instance;

/// Data queried for the exchange rate of a currency pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExchangeRate {
	/// Currency to get the exchange rate for.
	pub from: String,
	/// Destination currency for the exchange rate.
	pub to: String,
	/// Value of the exchange rate.
	pub rate: f64,
	/// Date the exchange rate corresponds to.
	pub date: DateTime<Utc>,
}

/// Data stored for the exchange rate of the currency pairs and price pairs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExchangeRates {
	/// Price pairs version
	pub version: PriceVersion,
	/// Currency pairs & Price pairs
	pub pairs: Vec<f64>,
	/// Date the exchange rate corresponds to.
	pub date: DateTime<Utc>,
	/// Price feeder data source unique name
	pub source_uid: u16,
	/// Feeder's signature
	#[serde(with = "secp_ser::sig_serde")]
	pub sig: Signature,
}

impl ExchangeRates {
	/// Construct the currency/price pairs from the raw ExchangeRate vector.
	pub fn from(rates: &Vec<ExchangeRate>) -> Result<ExchangeRates, Error> {
		if rates.len() != consensus::currency_pairs().len() {
			trace!(
				"currency pairs size not matched: input size = {}, consensus = {}",
				rates.len(),
				consensus::currency_pairs().len()
			);
			return Err(Error::Generic(
				"currency pairs size not matched".to_string(),
			));
		}

		// pre-checking the rates date to make sure they are on same timestamp
		for (a, b) in rates.iter().tuple_windows() {
			let time_a = a.date - Duration::seconds(a.date.second() as i64);
			let time_b = b.date - Duration::seconds(b.date.second() as i64);
			if time_a != time_b {
				trace!("exchange rates in different timestamp: {:?} vs {:?}", a, b);
				return Err(Error::Generic(
					"exchange rates in different timestamp".to_string(),
				));
			}
		}

		let date = rates[0].date - Duration::seconds(rates[0].date.second() as i64);
		let mut pairs: Vec<f64> = Vec::with_capacity(consensus::currency_pairs().len());
		for currency_pair in consensus::currency_pairs() {
			let index = rates
				.iter()
				.position(|r| format!("{}2{}", r.from, r.to) == *currency_pair)
				.ok_or(Error::NotFound("v0 pairs".to_string()))?;
			pairs.push(rates[index].rate);
		}

		Ok(ExchangeRates {
			version: PriceVersion::default(),
			source_uid: 0, // to be updated later when signing
			pairs,
			date,
			sig: Signature::from(secp::ffi::Signature::new()), // to be updated later when signing
		})
	}

	/// msg = hash(self without 'source_uid' and 'sig' fields)
	pub fn price_sig_msg(&self) -> Result<secp::Message, Error> {
		let mut data: Vec<u8> = vec![];

		//todo: to avoid 'source_uid' and 'sig' serialization here, so as to have a simple 'data.hash()' in next line
		ser::serialize_default(&mut data, self)?;
		let hash = data[..data.len() - secp::COMPACT_SIGNATURE_SIZE - 2]
			.to_vec()
			.hash();

		let msg = secp::Message::from_slice(&hash.as_bytes())?;
		Ok(msg)
	}

	//	/ Verify the price proof validity. Entails getting the corresponding public key of
	//	/ the price feeder source_uid and checking the signature verifies with the price as message.
	//	pub fn verify(&self) -> Result<(), Error> {
	//		let secp = static_secp_instance();
	//		let secp = secp.lock();
	//		let pubkey = &self.excess.to_pubkey(&secp)?;
	//		if !secp::aggsig::verify_single(
	//			&secp,
	//			&self.sig,
	//			&self.price_sig_msg()?,
	//			None,
	//			&pubkey,
	//			Some(&pubkey),
	//			None,
	//			false,
	//		) {
	//			return Err(Error::IncorrectSignature);
	//		}
	//		Ok(())
	//	}
}

impl Readable for ExchangeRates {
	fn read(reader: &mut dyn Reader) -> Result<ExchangeRates, ser::Error> {
		let version = PriceVersion::read(reader)?;
		let source_uid = reader.read_u16()?;
		let pairs_len = reader.read_u32()?;
		let pairs = read_multi(reader, pairs_len as u64)?;
		let timestamp = reader.read_i64()?;
		let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);
		let sig = secp::Signature::read(reader)?;
		Ok(ExchangeRates {
			version,
			source_uid,
			pairs,
			date,
			sig,
		})
	}
}

impl Writeable for ExchangeRates {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.version.write(writer)?;
		writer.write_u16(self.source_uid)?;
		writer.write_u32(self.pairs.len() as u32)?;
		self.pairs.write(writer)?;
		writer.write_i64(self.date.timestamp())?;
		self.sig.write(writer)?;

		Ok(())
	}
}

/// Some type safety around price versioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PriceVersion(pub u16);

impl Default for PriceVersion {
	fn default() -> PriceVersion {
		PriceVersion(0)
	}
}

// self-conscious increment function courtesy of Jasper
impl PriceVersion {
	#[allow(dead_code)]
	fn next(&self) -> Self {
		Self(self.0 + 1)
	}
}

impl PriceVersion {
	/// Constructor taking the provided version.
	pub fn new(version: u16) -> PriceVersion {
		PriceVersion(version)
	}
}

impl From<PriceVersion> for u16 {
	fn from(v: PriceVersion) -> u16 {
		v.0
	}
}

impl Writeable for PriceVersion {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u16(self.0)
	}
}

impl Readable for PriceVersion {
	fn read(reader: &mut dyn Reader) -> Result<PriceVersion, ser::Error> {
		let version = reader.read_u16()?;
		Ok(PriceVersion(version))
	}
}

/// Errors thrown by Price validation
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
	/// Underlying Secp256k1 error (signature validation or invalid public key typically)
	#[fail(display = "Libsecp internal error: {}", _0)]
	Secp(secp::Error),
	/// Price Signature verification error.
	#[fail(display = "Price IncorrectSignature error")]
	IncorrectSignature,
	/// Underlying serialization error.
	#[fail(display = "Serialization error: {}", _0)]
	Serialization(ser::Error),
	/// NotFound error
	#[fail(display = "Pair not found: {}", _0)]
	NotFound(String),
	/// Generic error
	#[fail(display = "Generic Error: {}", _0)]
	Generic(String),
}

impl From<ser::Error> for Error {
	fn from(e: ser::Error) -> Error {
		Error::Serialization(e)
	}
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use gotts_util::to_hex;

	#[test]
	fn price_sig_msg() {
		let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0x5e19a248, 0), Utc);
		let rates = ExchangeRates {
			version: PriceVersion::default(),
			source_uid: 0,
			pairs: vec![
				7944.59_f64,
				138.95_f64,
				1.1116_f64,
				1.3111_f64,
				6.9481_f64,
				109.22_f64,
				1.3037_f64,
			],
			date,
			sig: Signature::from(secp::ffi::Signature::new()),
		};

		let msg = rates.price_sig_msg().unwrap();
		assert_eq!(
			msg,
			secp::Message::from_str(
				"b4de08c8eccd8214adafd8db438fcbd17afafb9d128066df2bc50b228ba1945a"
			)
			.unwrap(),
		);

		let mut data: Vec<u8> = vec![];
		ser::serialize_default(&mut data, &rates).unwrap();
		assert_eq!(data.len(), 72 + 64);
		assert_eq!(
			"000000000000000740bf08970a3d70a440615e66666666663ff1c91d14e3bcd33ff4fa43fe5c91d1401bcadab9f559b4405b4e147ae147ae3ff4dbf487fcb924000000005e19a248",
			to_hex(data[..data.len()-secp::COMPACT_SIGNATURE_SIZE].to_vec()),
		);
	}
}
