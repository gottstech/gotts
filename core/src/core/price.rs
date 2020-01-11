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

use chrono::{DateTime, Duration, Timelike, Utc};
use itertools::Itertools;

//use crate::util::secp::{self, Message, Signature};
use crate::ser::{self, Readable, Reader, Writeable, Writer};

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

/// Errors thrown by Price validation
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
	/// Wraps a serialization error for Writeable or Readable
	#[fail(display = "Serialization Error")]
	SerErr(String),
	/// Generic error
	#[fail(display = "Generic Error: {}", _0)]
	Generic(String),
}
