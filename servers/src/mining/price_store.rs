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

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::core::ser::{self, Readable, Reader, Writeable, Writer};
use gotts_store::{self, option_to_not_found, to_key, to_key_i64, Error};

const DB_NAME: &'static str = "price";
const STORE_SUBPATH: &'static str = "prices";

const EXCHANGE_RATE_PREFIX: u8 = 'e' as u8;

/// Data stored for the exchange rate of a currency pair.
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

impl Readable for ExchangeRate {
	fn read(reader: &mut dyn Reader) -> Result<ExchangeRate, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		let from = std::str::from_utf8(&data)
			.map_err(|_| ser::Error::CorruptedData)?
			.to_string();
		let data = reader.read_bytes_len_prefix()?;
		let to = std::str::from_utf8(&data)
			.map_err(|_| ser::Error::CorruptedData)?
			.to_string();
		let rate = reader.read_f64()?;
		let timestamp = reader.read_i64()?;
		Ok(ExchangeRate {
			from,
			to,
			rate,
			date: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc),
		})
	}
}

impl Writeable for ExchangeRate {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&self.from.as_bytes().to_vec())?;
		writer.write_bytes(&self.to.as_bytes().to_vec())?;
		writer.write_f64(self.rate)?;
		writer.write_i64(self.date.timestamp())
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

	pub fn save(&mut self, date: DateTime<Utc>, exchange_rate: ExchangeRate) -> Result<(), Error> {
		// Save the exchange rate data to the db.
		{
			let mut fromto = exchange_rate.from.clone();
			fromto.push('2');
			fromto.push_str(&exchange_rate.to);
			let key = to_key_i64(
				EXCHANGE_RATE_PREFIX,
				&mut fromto.as_bytes().to_vec(),
				date.timestamp(),
			);
			let batch = self.db.batch()?;
			batch.put_ser(&key, &exchange_rate)?;
			batch.commit()?
		}

		Ok(())
	}

	pub fn get(&self, id: &str) -> Result<ExchangeRate, Error> {
		let key = to_key(EXCHANGE_RATE_PREFIX, &mut id.as_bytes().to_vec());
		option_to_not_found(self.db.get_ser(&key), || format!("Key ID: {}", id))
			.map_err(|e| e.into())
	}

	fn delete(&mut self, id: &str, date: DateTime<Utc>) -> Result<(), Error> {
		// Delete the exchange rate data.
		{
			let key = to_key_i64(
				EXCHANGE_RATE_PREFIX,
				&mut id.as_bytes().to_vec(),
				date.timestamp(),
			);
			let batch = self.db.batch()?;
			batch.delete(&key)?;
			batch.commit()?
		}

		Ok(())
	}

	/// List all known prices
	/// Used for /v1/prices/all api endpoint
	pub fn all_prices(&self) -> Result<Vec<ExchangeRate>, Error> {
		let key = to_key(EXCHANGE_RATE_PREFIX, &mut "".to_string().into_bytes());
		Ok(self
			.db
			.iter::<ExchangeRate>(&key)?
			.map(|(_, v)| v)
			.collect::<Vec<_>>())
	}

	/// Iterate over all exchange rate data stored by the backend with same id
	pub fn iter_id<'a>(&'a self, id: &str) -> Box<dyn Iterator<Item = ExchangeRate> + 'a> {
		let key = to_key(EXCHANGE_RATE_PREFIX, &mut id.as_bytes().to_vec());
		Box::new(self.db.iter(&key).unwrap().map(|o| o.1))
	}

	/// Delete prices from the storage that satisfy some condition `predicate`
	pub fn delete_prices<F>(&self, predicate: F) -> Result<(), Error>
	where
		F: Fn(&ExchangeRate) -> bool,
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
			for rate in to_remove {
				let id = format!("{}2{}", rate.from, rate.to);
				let key = to_key_i64(
					EXCHANGE_RATE_PREFIX,
					&mut id.as_bytes().to_vec(),
					rate.date.timestamp(),
				);
				batch.delete(&key)?;
			}
			batch.commit()?;
		}

		Ok(())
	}
}
