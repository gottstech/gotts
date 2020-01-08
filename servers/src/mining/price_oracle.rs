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

use chrono::prelude::{DateTime, Utc};
use croaring::Bitmap;
use serde_json::{json, Value};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::api;
use crate::chain::{self, SyncState};
use crate::common::types::Error;
use crate::common::types::PriceOracleServerConfig;
use crate::util::StopState;

/// Represents the exchange rate for a currency pair.
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

		loop {
			if let Ok(rates) = create_price_msg(&oracle_server_url) {
				if let Err(e) = self.price_encode(&rates) {
					warn!("price_encode failed: {:?}", e);
				}
			}

			if self.stop_state.is_stopped() {
				break;
			}
			thread::sleep(Duration::from_secs(60));
		}
	}

	fn price_encode(&self, aggregated_rates: &Vec<ExchangeRate>) -> Result<(), Error> {
		let currencies = vec!["USD", "EUR", "CNY", "GBP", "CAD"];
		let mut calculated_rates: Vec<ExchangeRate> = vec![];

		// todo: pre-checking on the date to make sure the aggregated rates are on same timestamp.

		// firstly, get all x over JPY rates
		for from in currencies.clone() {
			let to = "JPY";
			let index = aggregated_rates
				.iter()
				.position(|r| r.from == from && r.to == to)
				.ok_or(Error::General(format!("price {}2{} not found", from, to)))?;
			calculated_rates.push(aggregated_rates[index].clone());
		}

		// secondly, calculate 1/(x/JPY) to get the rates of JPY over all x.
		for (index, to) in currencies.iter().enumerate() {
			let rate = ExchangeRate {
				from: "JPY".to_string(),
				to: to.to_string(),
				rate: 1f64 / calculated_rates[index].rate,
				date: calculated_rates[index].date,
			};
			calculated_rates.push(rate);
		}

		// thirdly, calculate all others
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

		// finally, calculate the difference
		let mut diff = aggregated_rates.clone();
		for rate in diff.iter_mut() {
			if rate.from == "BTC" || rate.from == "ETH" {
				continue;
			}
			if rate.to != "JPY" {
				let index = calculated_rates
					.iter()
					.position(|r| r.from == rate.from && r.to == rate.to)
					.ok_or(Error::General(format!(
						"price {}2{} not found",
						rate.from, rate.to
					)))?;
				rate.rate -= calculated_rates[index].rate;
			}
		}

		debug!(
			"diff rates = {}",
			serde_json::to_string_pretty(&diff).unwrap()
		);
		let mut encode_vector: Vec<i32> = vec![];
		for rate in diff.iter() {
			if rate.from == "BTC" || rate.from == "ETH" || rate.to == "JPY" {
				continue;
			}
			let price: i32 = (rate.rate * 10_000f64).round() as i32;
			encode_vector.push(price);
		}
		debug!(
			"diff rates = {}",
			serde_json::to_string(&encode_vector).unwrap()
		);

		// workaround for bitmap only support positive integer
		let mut u32_vector: Vec<u32> = vec![];
		for r in encode_vector.iter_mut() {
			if *r < 0 {
				u32_vector.push(-*r as u32);
			} else {
				u32_vector.push(*r as u32);
			}
		}

		let mut bitmap: Bitmap = u32_vector.into_iter().collect();
		let serialized_buffer = bitmap.serialize();
		debug!("diff rates bitmap serial len: {}", serialized_buffer.len());
		bitmap.run_optimize();
		let serialized_buffer = bitmap.serialize();
		debug!(
			"diff rates bitmap optimized serial len: {}",
			serialized_buffer.len()
		);
		Ok(())
	}
}
