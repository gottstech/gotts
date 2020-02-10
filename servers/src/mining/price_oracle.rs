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
use std::sync::{Arc, Weak};
use std::thread;
use std::time;

use super::price_store::PriceStore;
use crate::api;
use crate::chain::{self, SyncState};
use crate::common::types::Error;
use crate::common::types::PriceOracleServerConfig;
use crate::core::consensus;
use crate::core::core::price::{
	calculate_full_price_pairs, decode_price, encode_price, ExchangeRate, ExchangeRates,
};
use crate::core::core::verifier_cache::VerifierCache;
use crate::gotts::price_pool::PricePool;
use crate::p2p;
use crate::util::file::get_first_line;
use crate::util::secp::{self, Signature};
use crate::util::OneTime;
use crate::util::{RwLock, StopState};

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

// Connect to the wallet listener to get ExchangeRates signed and return the signature.
fn get_price_signed(
	wallet_listener_url: &str,
	owner_api_secret: &Option<String>,
	msg: secp::Message,
	key_id: &str,
) -> Result<(String, String), Error> {
	let url = format!("{}/v2/owner", wallet_listener_url);
	let req_body = json!({
		"jsonrpc": "2.0",
		"method": "sign_price",
		"id": 1,
		"params": {
			"msg": msg.to_string(),
			"key_id": key_id.clone()
		}
	});

	trace!("Sending sign_price request: {}", req_body);
	let req = api::client::create_post_request(url.as_str(), owner_api_secret.clone(), &req_body)?;
	let res: String = api::client::send_request(req).map_err(|e| {
		let report = format!(
			"Failed to sign_price from {}. Is the wallet listening? {}",
			wallet_listener_url, e
		);
		error!("{}", report);
		Error::WalletComm(report)
	})?;

	let res: Value = serde_json::from_str(&res).unwrap();
	trace!("Response: {}", res);
	if res["error"] != json!(null) {
		let report = format!(
			"Failed to sign_price from {}: Error: {}, Message: {}",
			wallet_listener_url, res["error"]["code"], res["error"]["message"]
		);
		error!("{}", report);
		return Err(Error::WalletComm(report));
	}

	let cb_data = res["result"]["Ok"].clone();
	trace!("cb_data: {}", cb_data);
	let (sig, pubkey) = match serde_json::from_value::<(String, String)>(cb_data) {
		Ok(r) => (r.0, r.1),
		Err(e) => {
			let report = format!("Couldn't deserialize : {}", e);
			error!("{}", report);
			return Err(Error::WalletComm(report));
		}
	};

	debug!("get_price_signed: sig = {}, pubkey = {}", sig, pubkey);
	Ok((sig, pubkey))
}

pub struct PriceOracleServer {
	store: Arc<PriceStore>,
	config: PriceOracleServerConfig,
	stop_state: Arc<StopState>,
	chain: Arc<chain::Chain>,
	price_pool: Arc<RwLock<PricePool>>,
	peers: OneTime<Weak<p2p::Peers>>,
	verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	sync_state: Arc<SyncState>,
}

impl PriceOracleServer {
	/// Creates a new price feeder oracle server.
	pub fn new(
		db_root: String,
		config: PriceOracleServerConfig,
		chain: Arc<chain::Chain>,
		price_pool: Arc<RwLock<PricePool>>,
		peers: Arc<p2p::Peers>,
		verifier_cache: Arc<RwLock<dyn VerifierCache>>,
		stop_state: Arc<StopState>,
	) -> Result<PriceOracleServer, Error> {
		let store = Arc::new(PriceStore::new(&db_root)?);
		let p: OneTime<Weak<p2p::Peers>> = OneTime::new();
		p.init(Arc::downgrade(&peers));

		Ok(PriceOracleServer {
			store,
			config,
			stop_state,
			chain,
			price_pool,
			peers: p,
			verifier_cache,
			sync_state: Arc::new(SyncState::new()),
		})
	}

	fn peers(&self) -> Arc<p2p::Peers> {
		self.peers
			.borrow()
			.upgrade()
			.expect("Failed to upgrade weak ref to our peers.")
	}

	/// "main()" - Starts the price feeder oracle server.
	pub fn run_loop(&mut self, sync_state: Arc<SyncState>) {
		info!("Starting price feeder oracle server");

		self.sync_state = sync_state;
		let oracle_server_url = self
			.config
			.oracle_server_url
			.clone()
			.unwrap_or("http://127.0.0.1:3518".to_string());
		let price_feeder_source_uid = self.config.price_feeder_source_uid;
		let owner_api_secret = get_first_line(self.config.owner_api_secret_path.clone());
		let price_feeder_key_id = self
			.config
			.price_feeder_key_id
			.clone()
			.unwrap_or("03000000000000000000000000".to_string());

		warn!(
			"Price feeder oracle server started on {}",
			oracle_server_url,
		);

		'restart_querying: loop {
			// get the latest chain state
			let head = self.chain.head().unwrap();
			let head = self.chain.get_block_header(&head.last_block_h).unwrap();

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

				if let Ok(mut pairs) = ExchangeRates::from(&rates, price_feeder_source_uid) {
					if let Ok((sig, pubkey)) = get_price_signed(
						&self.config.wallet_owner_api_listener_url,
						&owner_api_secret,
						pairs.price_sig_msg().unwrap(),
						&price_feeder_key_id,
					) {
						if let Some(source_uid) = consensus::price_feeders_list()
							.iter()
							.position(|p| *p == pubkey)
						{
							pairs.sig = Signature::from_str(&sig).unwrap();

							if let Err(e) =
								self.price_pool.write().add_to_pool(pairs.clone(), &head)
							{
								debug!(
									"price from source {} - add_to_pool fail: {}",
									source_uid,
									e.to_string()
								);
								thread::sleep(time::Duration::from_secs(1));
								continue 'restart_querying;
							}

							// save into database
							self.store.save(&pairs).unwrap();
							if let Ok(pairs_copy) = self.store.get(pairs.source_uid, pairs.date) {
								debug!(
									"price pairs read from local lmdb: {}",
									serde_json::to_string(&pairs_copy).unwrap()
								);
							}
						}
					}
				}

				if let Err(e) = calculate_full_price_pairs(&rates) {
					warn!("price_encode failed: {:?}", e);
				} else {
					let fixed_point_price = encode_price(&rates.iter().map(|r| r.rate).collect());
					debug!("deco price pairs = {:?}", decode_price(&fixed_point_price));
				}
			}

			if self.stop_state.is_stopped() {
				break;
			}
			thread::sleep(time::Duration::from_secs(60));
		}
	}
}
