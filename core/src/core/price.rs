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
use crate::core::hash::{DefaultHashable, Hash, Hashed};
use crate::core::pmmr::{VecBackend, PMMR};
use crate::core::verifier_cache::VerifierCache;
use crate::keychain::{ExtKeychain, Keychain};
use crate::libtx::secp_ser;
use crate::ser::{
	self, read_multi, FixedLength, PMMRIndexHashable, PMMRable, Readable, Reader,
	VerifySortedAndUnique, Writeable, Writer,
};
use crate::util::secp::{self, PublicKey, Signature};
use crate::util::static_secp_instance;
use crate::util::RwLock;

use std::cmp::Ordering;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
hashable_ord!(ExchangeRates);

/// ExchangeRates are "variable size" but we need to implement FixedLength for legacy reasons.
impl FixedLength for ExchangeRates {
	const LEN: usize = 0;
}

impl PMMRable for ExchangeRates {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

impl PMMRIndexHashable for ExchangeRates {
	fn hash_with_index(&self, index: u64) -> Hash {
		(index, self).hash()
	}
}

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
			version: PriceVersion(0),
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

		{
			let mut verifier = verifier.write();
			if verifier
				.filter_prices_sig_unverified(&[self.clone()])
				.is_empty()
			{
				return Ok(());
			}
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

		let mut verifier = verifier.write();
		verifier.add_prices_sig_verified(&[self.clone()]);
		Ok(())
	}
}

/// Batch signature verification.
pub fn batch_sig_verify(prices: &Vec<ExchangeRates>) -> Result<(), Error> {
	let len = prices.len();
	let mut sigs: Vec<secp::Signature> = Vec::with_capacity(len);
	let mut pubkeys: Vec<secp::key::PublicKey> = Vec::with_capacity(len);
	let mut msgs: Vec<secp::Message> = Vec::with_capacity(len);

	let secp = static_secp_instance();
	let secp = secp.lock();

	for price in prices {
		sigs.push(price.sig.clone());
		pubkeys.push(PublicKey::from_str(
			consensus::price_feeders_list()[price.source_uid as usize],
		)?);
		msgs.push(price.price_sig_msg()?);
	}

	if !secp::aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
		return Err(Error::IncorrectSignature);
	}

	Ok(())
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
pub struct VersionedPrice {
	/// Price version
	pub version: PriceVersion,
	/// Fixed Point Price Data, variable length vector
	pub prices: Vec<i64>,
}

impl Writeable for VersionedPrice {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.version.write(writer)?;
		writer.write_u16(self.prices.len() as u16)?;
		self.prices.write(writer)?;
		Ok(())
	}
}

impl Readable for VersionedPrice {
	fn read(reader: &mut dyn Reader) -> Result<VersionedPrice, ser::Error> {
		let version = PriceVersion::read(reader)?;
		let prices_len = reader.read_u16()?;
		let prices = read_multi(reader, prices_len as u64)?;

		Ok(VersionedPrice { version, prices })
	}
}

impl VersionedPrice {
	/// Size of this object
	pub fn size(&self) -> usize {
		self.prices.len() * std::mem::size_of::<i64>() + std::mem::size_of::<u16>()
	}
}

impl Default for VersionedPrice {
	fn default() -> VersionedPrice {
		let mut zero_prices: Vec<f64> = Vec::with_capacity(consensus::currency_pairs().len());
		for _ in 0..consensus::currency_pairs().len() {
			zero_prices.push(0f64);
		}
		VersionedPrice {
			version: PriceVersion(0),
			prices: encode_price(&zero_prices),
		}
	}
}

/// Util to calculate MMR root
pub fn prices_root(prices: &Vec<ExchangeRates>) -> Result<(Hash, u16), Error> {
	let mut ba = VecBackend::new();
	let mut pmmr = PMMR::new(&mut ba);
	for price in prices {
		pmmr.push(price).unwrap();
	}
	Ok((
		pmmr.root().map_err(|_| Error::InvalidMMRroot)?,
		pmmr.unpruned_size() as u16,
	))
}

/// Util to calculate median price based on selected prices list
pub fn get_median_price(prices: &Vec<ExchangeRates>) -> Result<VersionedPrice, Error> {
	if prices.is_empty() {
		return Err(Error::EmptyPrice);
	}

	prices.verify_sorted_and_unique()?;
	if prices
		.iter()
		.position(|r| r.version != PriceVersion(0))
		.is_some()
	{
		return Err(Error::InvalidVersion);
	}

	let pairs_size = consensus::currency_pairs().len();
	if prices
		.iter()
		.position(|r| r.pairs.len() != pairs_size)
		.is_some()
	{
		return Err(Error::InvalidSize);
	}

	let float_point_prices: Vec<Vec<f64>> = prices.iter().map(|r| r.pairs.clone()).collect();
	let mut median_prices: Vec<i64> = Vec::with_capacity(pairs_size);
	for i in 0..pairs_size {
		let mut price_list: Vec<i64> =
			encode_price(&float_point_prices.iter().map(|a| a[i]).collect());
		price_list.sort();
		assert_ne!(price_list.len(), 0);
		median_prices.push(price_list[price_list.len() / 2]);
	}

	Ok(VersionedPrice {
		version: PriceVersion(0),
		prices: median_prices,
	})
}

/// Some type safety around price versioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PriceVersion(pub u16);

impl From<PriceVersion> for u16 {
	fn from(ver: PriceVersion) -> u16 {
		ver.0
	}
}

impl From<u16> for PriceVersion {
	fn from(v: u16) -> PriceVersion {
		PriceVersion(v)
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
	/// InvalidSource error
	#[fail(display = "Invalid source: {}", _0)]
	InvalidSource(u16),
	/// Outdated error
	#[fail(display = "Outdated price")]
	Outdated,
	/// Invalid version
	#[fail(display = "Invalid version")]
	InvalidVersion,
	/// Invalid size
	#[fail(display = "Invalid size")]
	InvalidSize,
	/// Empty price
	#[fail(display = "Empty price")]
	EmptyPrice,
	/// Invalid MMR root
	#[fail(display = "Invalid MMR root")]
	InvalidMMRroot,
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

/// Util to convert float price into fixed point price
pub fn encode_price(prices: &Vec<f64>) -> Vec<i64> {
	// convert float64 to i64 with 10^-9 precision
	let price_pairs: Vec<i64> = prices
		.iter()
		.map(|r| (*r * GOTTS_PRICE_PRECISION).round() as i64)
		.collect();

	trace!("encode price pairs = {:?}", price_pairs);
	price_pairs
}

/// Util to convert fixed point price into float price
pub fn decode_price(encoded: &Vec<i64>) -> Vec<f64> {
	// convert i64 to float64 with 10^-9 precision
	let decoded: Vec<f64> = encoded
		.iter()
		.map(|r| *r as f64 / GOTTS_PRICE_PRECISION)
		.collect();
	trace!("decode price pairs = {:?}", decoded);
	decoded
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

/// Util for AutomatedTest price feeder keychain
pub fn auto_test_feeder_keychain() -> ExtKeychain {
	let rec_phrase_1 =
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch";
	ExtKeychain::from_mnemonic(rec_phrase_1, "", false).unwrap()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::consensus;
	use crate::keychain::ExtKeychain;
	use gotts_util::to_hex;

	#[test]
	fn test_automated_test_feeder_keychain() {
		let keychain = auto_test_feeder_keychain();

		let key_id_0 = ExtKeychain::derive_key_id(3, 1, 0, 0, 0);
		let prikey_0 = keychain.derive_key(&key_id_0).unwrap();
		let pubkey_0 = PublicKey::from_secret_key(keychain.secp(), &prikey_0).unwrap();

		let price_feeders_list = consensus::AUTOTEST_PRICE_FEEDERS_LIST;
		assert_eq!(pubkey_0.to_string(), price_feeders_list[0]);

		let key_id_1 = ExtKeychain::derive_key_id(3, 1, 0, 1, 0);
		let prikey_1 = keychain.derive_key(&key_id_1).unwrap();
		let pubkey_1 = PublicKey::from_secret_key(keychain.secp(), &prikey_1).unwrap();
		assert_eq!(pubkey_1.to_string(), price_feeders_list[1]);

		let key_id_2 = ExtKeychain::derive_key_id(3, 1, 0, 2, 0);
		let prikey_2 = keychain.derive_key(&key_id_2).unwrap();
		let pubkey_2 = PublicKey::from_secret_key(keychain.secp(), &prikey_2).unwrap();
		assert_eq!(pubkey_2.to_string(), price_feeders_list[2]);
	}

	#[test]
	fn price_sig_msg() {
		let date = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0x5e19a248, 0), Utc);
		let rates = ExchangeRates {
			version: PriceVersion(0),
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
				"b0d37fd9d3a0c78543878716f0623b01188305b9bfc81f9b2ee71d0cba595522"
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
