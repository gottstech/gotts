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
use crate::core::hash::{DefaultHashable, Hashed};
use crate::core::verifier_cache::VerifierCache;
use crate::libtx::secp_ser;
use crate::ser::{self, read_multi, Readable, Reader, Writeable, Writer};
use crate::util::secp::{self, PublicKey, Signature};
use crate::util::static_secp_instance;
use crate::util::{to_hex, RwLock};
use diff0::{self, diff0_compress, diff0_decompress};

use std::sync::Arc;

/// The price data precision in fraction (1/x)
pub const GOTTS_PRICE_PRECISION: f64 = 1_000_000_000.0_f64;

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

impl DefaultHashable for ExchangeRates {}

impl ExchangeRates {
	/// Construct the currency/price pairs from the raw ExchangeRate vector.
	pub fn from(
		rates: &Vec<ExchangeRate>,
		price_feeder_source_uid: u16,
	) -> Result<ExchangeRates, Error> {
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
			version: PriceVersion::Raw(0),
			source_uid: price_feeder_source_uid,
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

	/// Validates all relevant parts of a price.
	/// - Checks the timestamp is the latest.
	/// - Checks the source is one of the price_feeders_list.
	/// - Checks the signature.
	pub fn validate(
		&self,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		header_time: DateTime<Utc>,
	) -> Result<(), Error> {
		if self.source_uid as usize >= consensus::price_feeders_list().len() {
			return Err(Error::InvalidSource(self.source_uid));
		}

		if self.date < header_time {
			debug!(
				"outdated price received: {}",
				self.date.format("%Y-%m-%d %H:%M:%S").to_string()
			);
			return Err(Error::Outdated);
		}

		let secp = static_secp_instance();
		let secp = secp.lock();
		let pubkey =
			PublicKey::from_str(consensus::price_feeders_list()[self.source_uid as usize])?;
		if !secp::aggsig::verify_single(
			&secp,
			&self.sig,
			&self.price_sig_msg()?,
			None,
			&pubkey,
			Some(&pubkey),
			None,
			false,
		) {
			return Err(Error::IncorrectSignature);
		}
		Ok(())
	}
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

/// Encoded Price Data with PriceVersion
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VersionedPriceEncoded {
	/// Price version
	pub version: PriceVersion,
	/// Encoded Price Data, variable length vector
	pub encoded_price: Vec<u8>,
}

impl Writeable for VersionedPriceEncoded {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.version.write(writer)?;
		writer.write_u16(self.encoded_price.len() as u16)?;
		writer.write_fixed_bytes(&self.encoded_price)
	}
}

impl Readable for VersionedPriceEncoded {
	fn read(reader: &mut dyn Reader) -> Result<VersionedPriceEncoded, ser::Error> {
		let version = PriceVersion::read(reader)?;
		let encoded_price_len = reader.read_u16()?;
		let encoded_price = reader.read_fixed_bytes(encoded_price_len as usize)?;
		Ok(VersionedPriceEncoded {
			version,
			encoded_price,
		})
	}
}

impl VersionedPriceEncoded {
	/// Constructor
	pub fn new(version: u16, encoded_price: Vec<u8>, is_raw: bool) -> VersionedPriceEncoded {
		let version = match is_raw {
			true => PriceVersion::Raw(version),
			false => PriceVersion::Diff(version),
		};
		VersionedPriceEncoded {
			version,
			encoded_price,
		}
	}

	/// Size of this object
	pub fn size(&self) -> usize {
		self.encoded_price.len() + 2
	}
}

// The default methold is only for test.
//impl Default for VersionedPriceEncoded {
//	fn default() -> VersionedPriceEncoded {
//		VersionedPriceEncoded::new(0)
//	}
//}

/// Some type safety around price versioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PriceVersion {
	/// Differential Price
	Diff(u16),
	/// Raw Price
	Raw(u16),
}

impl From<PriceVersion> for u16 {
	fn from(ver: PriceVersion) -> u16 {
		match ver {
			PriceVersion::Diff(v) => v | 0x8000u16,
			PriceVersion::Raw(v) => v & 0x7fffu16,
		}
	}
}

impl From<u16> for PriceVersion {
	fn from(v: u16) -> PriceVersion {
		match v >> 15 {
			0 => PriceVersion::Diff(v & 0x7fffu16),
			_ => PriceVersion::Raw(v & 0x7fffu16),
		}
	}
}

impl Writeable for PriceVersion {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u16(u16::from(self.clone()))
	}
}

impl Readable for PriceVersion {
	fn read(reader: &mut dyn Reader) -> Result<PriceVersion, ser::Error> {
		let version = reader.read_u16()?;
		Ok(PriceVersion::from(version))
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
	/// InvalidSource error
	#[fail(display = "Invalid source: {}", _0)]
	InvalidSource(u16),
	/// Outdated error
	#[fail(display = "Outdated price")]
	Outdated,
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

/// Possible errors when interacting with the transaction pool.
#[derive(Clone, Debug, Fail, Eq, PartialEq)]
pub enum PoolError {
	/// An invalid pool entry caused by underlying tx validation error
	#[fail(display = "Invalid Price - {}", _0)]
	InvalidPrice(Error),
	/// Attempt to add a duplicate price to the pool.
	#[fail(display = "Duplicate price")]
	DuplicatePrice,
	/// Price pool is over capacity, can't accept more prices
	#[fail(display = "Over Capacity")]
	OverCapacity,
	/// Other kinds of error (not yet pulled out into meaningful errors).
	#[fail(display = "General pool error - {}", _0)]
	Other(String),
}

impl From<Error> for PoolError {
	fn from(e: Error) -> PoolError {
		PoolError::InvalidPrice(e)
	}
}

/// Diff0 compression encoder to convert float price into fixed point binary
pub fn encode_price_feeder(
	previous_price_pairs: &Option<Vec<f64>>,
	aggregated_rates: &Vec<ExchangeRate>,
) -> Vec<u8> {
	let price_pairs: Vec<f64> = aggregated_rates.iter().map(|r| r.rate).collect();
	let precision = GOTTS_PRICE_PRECISION;

	let pairs = if let Some(previous) = previous_price_pairs {
		// only encode the difference values, with 10^-9 precision.
		assert_eq!(previous.len(), price_pairs.len());
		let diff: Vec<f64> = price_pairs
			.iter()
			.zip(previous)
			.map(|(a, b)| ((a - b) * precision).round() / precision)
			.collect();
		debug!("diff price pairs = {:?}", diff);
		diff
	} else {
		// encode the raw values
		debug!("raw price pairs = {:?}", price_pairs);
		price_pairs
	};

	// convert float64 to i64 with 10^-9 precision
	let i64_pairs: Vec<i64> = pairs
		.iter()
		.map(|r| (*r * precision).round() as i64)
		.collect();

	// encode
	let serialized_buffer = diff0_compress(i64_pairs).unwrap();
	debug!(
		"serialized_buffer: len = {}, data = {}",
		serialized_buffer.len(),
		to_hex(serialized_buffer.clone())
	);
	serialized_buffer
}

/// Util to calculate full price pairs from the basic pairs
pub fn calculate_full_price_pairs(aggregated_rates: &Vec<ExchangeRate>) -> Result<(), Error> {
	let currencies_a = vec!["EUR", "GBP", "BTC", "ETH"];
	let currencies_b = vec!["CNY", "JPY", "CAD"];
	let mut calculated_rates: Vec<ExchangeRate> = vec![];

	// firstly, get/calculate all x over USD rates
	for from in currencies_a.clone() {
		let to = "USD";
		let index = aggregated_rates
			.iter()
			.position(|r| r.from == from && r.to == to)
			.ok_or(Error::Generic(format!("price {}2{} not found", from, to)))?;
		calculated_rates.push(aggregated_rates[index].clone());
	}
	for to in currencies_b.clone().into_iter() {
		let index = aggregated_rates
			.iter()
			.position(|r| r.from == "USD" && r.to == to)
			.ok_or(Error::Generic(format!("price USD2{} not found", to)))?;
		let rate = ExchangeRate {
			from: to.to_string(),
			to: "USD".to_string(),
			rate: 1f64 / aggregated_rates[index].rate,
			date: aggregated_rates[index].date,
		};
		calculated_rates.push(rate);
	}

	// secondly, calculate/get 1/(x/USD) to get the rates of USD over all x.
	for (index, to) in currencies_a.iter().enumerate() {
		let rate = ExchangeRate {
			from: "USD".to_string(),
			to: to.to_string(),
			rate: 1f64 / calculated_rates[index].rate,
			date: calculated_rates[index].date,
		};
		calculated_rates.push(rate);
	}
	for to in currencies_b.clone().into_iter() {
		let index = aggregated_rates
			.iter()
			.position(|r| r.from == "USD" && r.to == to)
			.ok_or(Error::Generic(format!("price USD2{} not found", to)))?;
		calculated_rates.push(aggregated_rates[index].clone());
	}

	// thirdly, calculate all others
	let currencies = [&currencies_a[..], &currencies_b[..]].concat();
	for (i, from) in currencies.iter().enumerate() {
		for (j, to) in currencies.iter().enumerate() {
			if i != j {
				let rate = ExchangeRate {
					from: from.to_string(),
					to: to.to_string(),
					rate: calculated_rates[i].rate / calculated_rates[j].rate,
					date: calculated_rates[i].date,
				};
				calculated_rates.push(rate);
			}
		}
	}

	trace!(
		"price pairs = {}",
		serde_json::to_string_pretty(&calculated_rates).unwrap()
	);

	Ok(())
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
