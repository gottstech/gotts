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

//! Mining Price Feed Oracle Server

use chrono::{Duration, Timelike};
use itertools::Itertools;
use serde_json::{json, Value};
use std::sync::Arc;
use std::thread;
use std::time;

use super::price_store::ExchangeRate;
use crate::api;
use crate::chain::{self, SyncState};
use crate::common::types::Error;
use crate::common::types::PriceOracleServerConfig;
use crate::util::StopState;
use diff0::{self, diff0_compress, diff0_decompress};
use gotts_util::to_hex;

/// The price data precision in fraction (1/x)
pub const GOTTS_PRICE_PRECISION: f64 = 1_000_000_000.0_f64;

/// Call the oracle API to create a price feeder message.
fn create_price_msg(dest: &str) -> Result<Vec<ExchangeRate>, Error> {
	let url = format!("{}/v1/json", dest);
	let req_body = json!({
		"jsonrpc": "2.0",
		"method": "get_aggregated",
		"id": 1,
		"params": null
	});

	let req = api::client::create_post_request(url.as_str(), None, &req_body)?;
	let res: String = api::client::send_request(req).map_err(|e| {
		let report = format!("Failed to get price from oracle {}. {}", dest, e);
		error!("{}", report);
		Error::WalletComm(report)
	})?;

	let res: Value = serde_json::from_str(&res).unwrap();
	if res["error"] != json!(null) {
		let report = format!(
			"Failed to get aggregated exchange rate from {}: Error: {}, Message: {}",
			dest, res["error"]["code"], res["error"]["message"]
		);
		error!("{}", report);
		return Err(Error::WalletComm(report));
	}

	let rates = res["result"]["Ok"].clone();
	let ret_val = match serde_json::from_value::<Vec<ExchangeRate>>(rates) {
		Ok(r) => r,
		Err(e) => {
			let report = format!("Couldn't deserialize Vec<ExchangeRate>: {}", e);
			error!("{}", report);
			return Err(Error::WalletComm(report));
		}
	};

	Ok(ret_val)
}

pub struct PriceOracleServer {
	id: String,
	config: PriceOracleServerConfig,
	stop_state: Arc<StopState>,
	chain: Arc<chain::Chain>,
	sync_state: Arc<SyncState>,
}

impl PriceOracleServer {
	/// Creates a new price feeder oracle server.
	pub fn new(
		config: PriceOracleServerConfig,
		chain: Arc<chain::Chain>,
		stop_state: Arc<StopState>,
	) -> PriceOracleServer {
		PriceOracleServer {
			id: String::from("0"),
			config,
			stop_state,
			chain,
			sync_state: Arc::new(SyncState::new()),
		}
	}

	/// "main()" - Starts the price feeder oracle server.
	pub fn run_loop(&mut self, sync_state: Arc<SyncState>) {
		info!(
			"(Server ID: {}) Starting price feeder oracle server",
			self.id,
		);

		self.sync_state = sync_state;
		let oracle_server_url = self
			.config
			.oracle_server_url
			.clone()
			.unwrap_or("http://127.0.0.1:3518".to_string());

		warn!(
			"Price feeder oracle server started on {}",
			oracle_server_url,
		);

		let precision = GOTTS_PRICE_PRECISION;
		let mut prev_price_rates: Option<Vec<f64>> = None;
		'restart_querying: loop {
			if let Ok(rates) = create_price_msg(&oracle_server_url) {
				// pre-checking on the date to make sure the aggregated rates are on same timestamp.
				for (a, b) in rates.iter().tuple_windows() {
					let time_a = a.date - Duration::seconds(a.date.second() as i64);
					let time_b = b.date - Duration::seconds(b.date.second() as i64);
					if time_a != time_b {
						debug!(
							"aggregated rates at different timestamp: {:?} vs {:?}",
							a, b
						);
						thread::sleep(time::Duration::from_secs(1));
						continue 'restart_querying;
					}
				}

				if let Err(e) = self.calculate_full_price_pairs(&rates) {
					warn!("price_encode failed: {:?}", e);
				} else {
					let serialized_price = self.encode_price_feeder(&prev_price_rates, &rates);
					prev_price_rates = Some(rates.iter().map(|r| r.rate).collect());
					let decoded_diffs = diff0_decompress(serialized_price).unwrap();
					// convert i64 to float64 with 10^-9 precision
					let diffs: Vec<f64> = decoded_diffs
						.iter()
						.map(|r| *r as f64 / precision)
						.collect();
					debug!("deco price pairs = {:?}", diffs);
				}
			}

			if self.stop_state.is_stopped() {
				break;
			}
			thread::sleep(time::Duration::from_secs(60));
		}
	}

	fn encode_price_feeder(
		&self,
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

	fn calculate_full_price_pairs(
		&self,
		aggregated_rates: &Vec<ExchangeRate>,
	) -> Result<(), Error> {
		let currencies_a = vec!["EUR", "GBP", "BTC", "ETH"];
		let currencies_b = vec!["CNY", "JPY", "CAD"];
		let mut calculated_rates: Vec<ExchangeRate> = vec![];

		// firstly, get/calculate all x over USD rates
		for from in currencies_a.clone() {
			let to = "USD";
			let index = aggregated_rates
				.iter()
				.position(|r| r.from == from && r.to == to)
				.ok_or(Error::General(format!("price {}2{} not found", from, to)))?;
			calculated_rates.push(aggregated_rates[index].clone());
		}
		for to in currencies_b.clone().into_iter() {
			let index = aggregated_rates
				.iter()
				.position(|r| r.from == "USD" && r.to == to)
				.ok_or(Error::General(format!("price USD2{} not found", to)))?;
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
				.ok_or(Error::General(format!("price USD2{} not found", to)))?;
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
}
