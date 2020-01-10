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

//! Storage implementation for price feeder data.

use chrono::{DateTime, Duration, Timelike, Utc};
use itertools::Itertools;

//use crate::util::secp::{self, Message, Signature};
use crate::core::ser::{self, Readable, Reader, Writeable, Writer};
use gotts_store::{self, option_to_not_found, to_i64_key, to_key, to_key_i64_b, Error};

const DB_NAME: &'static str = "price";
const STORE_SUBPATH: &'static str = "prices";

const EXCHANGE_RATES_PREFIX: u8 = 'e' as u8;

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
	pub version: u16,
	/// Price feeder data source unique name
	pub source_uid: String,
	/// Currency pairs & Price pairs
	pub pairs: Vec<(String, f64)>,
	/// Date the exchange rate corresponds to.
	pub date: DateTime<Utc>,
}

impl ExchangeRates {
	/// Construct the currency/price pairs from the raw ExchangeRate vector.
	pub fn from(rates: &Vec<ExchangeRate>) -> Result<ExchangeRates, Error> {
		if rates.is_empty() {
			return Err(Error::Generic("empty rates".to_string()));
		}

		// pre-checking on the date to make sure they are on same timestamp
		for (a, b) in rates.iter().tuple_windows() {
			let time_a = a.date - Duration::seconds(a.date.second() as i64);
			let time_b = b.date - Duration::seconds(b.date.second() as i64);
			if time_a != time_b {
				return Err(Error::Generic(
					"exchange rates in different timestamp".to_string(),
				));
			}
		}

		let date = rates[0].date - Duration::seconds(rates[0].date.second() as i64);
		let pairs = rates
			.iter()
			.map(|r| (format!("{}2{}", r.from, r.to), r.rate))
			.collect();

		Ok(ExchangeRates {
			version: 0,
			source_uid: "gotts".to_string(),
			pairs,
			date,
		})
	}
}

impl Readable for ExchangeRates {
	fn read(reader: &mut dyn Reader) -> Result<ExchangeRates, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

impl Writeable for ExchangeRates {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

/// Storage facility for price data.
pub struct PriceStore {
	db: gotts_store::Store,
}

impl PriceStore {
	/// Instantiates a new price store under the provided root path.
	pub fn new(db_root: &str) -> Result<PriceStore, Error> {
		let db = gotts_store::Store::new(db_root, Some(DB_NAME), Some(STORE_SUBPATH), None)?;
		Ok(PriceStore { db })
	}

	pub fn save(&self, pairs: &ExchangeRates) -> Result<(), Error> {
		let key = to_key_i64_b(
			EXCHANGE_RATES_PREFIX,
			&mut pairs.source_uid.as_bytes().to_vec(),
			pairs.date.timestamp(),
		);
		let batch = self.db.batch()?;
		batch.put_ser(&key, pairs)?;
		batch.commit()?;

		Ok(())
	}

	pub fn get(&self, source_uid: &str, date: DateTime<Utc>) -> Result<ExchangeRates, Error> {
		let key = to_key_i64_b(
			EXCHANGE_RATES_PREFIX,
			&mut source_uid.as_bytes().to_vec(),
			date.timestamp(),
		);
		option_to_not_found(self.db.get_ser(&key), || {
			format!("Source: {} date: {}", source_uid, date)
		})
		.map_err(|e| e.into())
	}

	pub fn delete(&self, source_uid: &str, date: DateTime<Utc>) -> Result<(), Error> {
		let key = to_key_i64_b(
			EXCHANGE_RATES_PREFIX,
			&mut source_uid.as_bytes().to_vec(),
			date.timestamp(),
		);
		let batch = self.db.batch()?;
		batch.delete(&key)?;
		batch.commit()?;

		Ok(())
	}

	/// List all known prices
	/// Used for /v1/prices/all api endpoint
	pub fn all_prices(&self) -> Result<Vec<ExchangeRates>, Error> {
		let key = to_key(EXCHANGE_RATES_PREFIX, &mut "".to_string().into_bytes());
		Ok(self
			.db
			.iter::<ExchangeRates>(&key)?
			.map(|(_, v)| v)
			.collect::<Vec<_>>())
	}

	/// Iterate over all price pairs stored by the backend with same date
	pub fn iter_date<'a>(
		&'a self,
		date: DateTime<Utc>,
	) -> Box<dyn Iterator<Item = ExchangeRates> + 'a> {
		let key = to_i64_key(EXCHANGE_RATES_PREFIX, date.timestamp());
		Box::new(self.db.iter(&key).unwrap().map(|o| o.1))
	}

	/// Delete prices from the storage that satisfy some condition `predicate`
	pub fn delete_prices<F>(&self, predicate: F) -> Result<(), Error>
	where
		F: Fn(&ExchangeRates) -> bool,
	{
		let mut to_remove = vec![];

		for x in self.all_prices()? {
			if predicate(&x) {
				to_remove.push(x)
			}
		}

		// Delete prices in single batch
		if !to_remove.is_empty() {
			let batch = self.db.batch()?;
			for pairs in to_remove {
				let key = to_key_i64_b(
					EXCHANGE_RATES_PREFIX,
					&mut pairs.source_uid.as_bytes().to_vec(),
					pairs.date.timestamp(),
				);
				batch.delete(&key)?;
			}
			batch.commit()?;
		}

		Ok(())
	}
}
