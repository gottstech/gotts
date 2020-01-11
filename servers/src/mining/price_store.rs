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

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};

use crate::core::core::price::ExchangeRates;
use gotts_store::{self, option_to_not_found, to_i64_key, to_key, to_key_i64_b, Error};

const DB_NAME: &'static str = "price";
const STORE_SUBPATH: &'static str = "prices";

const EXCHANGE_RATES_PREFIX: u8 = 'e' as u8;

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
		let mut k = [0u8; 2];
		BigEndian::write_u16(&mut k, pairs.source_uid);

		let key = to_key_i64_b(
			EXCHANGE_RATES_PREFIX,
			&mut k.to_vec(),
			pairs.date.timestamp(),
		);
		let batch = self.db.batch()?;
		batch.put_ser(&key, pairs)?;
		batch.commit()?;

		Ok(())
	}

	pub fn get(&self, source_uid: u16, date: DateTime<Utc>) -> Result<ExchangeRates, Error> {
		let mut k = [0u8; 2];
		BigEndian::write_u16(&mut k, source_uid);

		let key = to_key_i64_b(EXCHANGE_RATES_PREFIX, &mut k.to_vec(), date.timestamp());
		option_to_not_found(self.db.get_ser(&key), || {
			format!("Source: {} date: {}", source_uid, date)
		})
		.map_err(|e| e.into())
	}

	pub fn delete(&self, source_uid: u16, date: DateTime<Utc>) -> Result<(), Error> {
		let mut k = [0u8; 2];
		BigEndian::write_u16(&mut k, source_uid);

		let key = to_key_i64_b(EXCHANGE_RATES_PREFIX, &mut k.to_vec(), date.timestamp());
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

		let mut k = [0u8; 2];

		// Delete prices in single batch
		if !to_remove.is_empty() {
			let batch = self.db.batch()?;
			for pairs in to_remove {
				BigEndian::write_u16(&mut k, pairs.source_uid);
				let key = to_key_i64_b(
					EXCHANGE_RATES_PREFIX,
					&mut k.to_vec(),
					pairs.date.timestamp(),
				);
				batch.delete(&key)?;
			}
			batch.commit()?;
		}

		Ok(())
	}
}
