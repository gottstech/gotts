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

//! Price Pool

use chrono::{Duration, Timelike};
use itertools::Itertools;
use serde_json::{json, Value};
use std::sync::{Arc, Weak};
use std::thread;
use std::time;

use crate::chain::{self, SyncState};
use crate::common::types::Error;
use crate::common::types::PriceOracleServerConfig;
use crate::core::consensus;
use crate::core::core::hash::{DefaultHashable, Hash, Hashed};
use crate::core::core::price::{self, ExchangeRates};
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::BlockHeader;
use crate::mining::price_oracle::PriceOracleServer;
use crate::p2p;
use crate::util::file::get_first_line;
use crate::util::secp::{self, Signature};
use crate::util::OneTime;
use crate::util::{to_hex, RwLock, StopState};
use diff0::{self, diff0_compress, diff0_decompress};

/// Price pool implementation
pub struct PricePool {
	/// Price Entries
	pub entries: Vec<ExchangeRates>,
	config: PriceOracleServerConfig,
	chain: Arc<chain::Chain>,
	peers: OneTime<Weak<p2p::Peers>>,
	verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	sync_state: Arc<SyncState>,
}

impl PricePool {
	/// Creates a new price pool.
	pub fn new(
		config: PriceOracleServerConfig,
		chain: Arc<chain::Chain>,
		verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	) -> PricePool {
		PricePool {
			entries: vec![],
			config,
			chain,
			peers: OneTime::new(),
			verifier_cache,
			sync_state: Arc::new(SyncState::new()),
		}
	}

	/// Setup the p2p server on the adapter
	pub fn init(&self, peers: Arc<p2p::Peers>) {
		self.peers.init(Arc::downgrade(&peers));
	}

	fn peers(&self) -> Arc<p2p::Peers> {
		self.peers
			.borrow()
			.upgrade()
			.expect("Failed to upgrade weak ref to our peers.")
	}

	/// Does the price pool contain an entry for the given price?
	pub fn contains_price(&self, hash: Hash) -> bool {
		self.entries.iter().any(|x| x.hash() == hash)
	}

	/// Add the given price to the pool.
	pub fn add_to_pool(
		&mut self,
		price: ExchangeRates,
		header: &BlockHeader,
	) -> Result<(), PoolError> {
		// Quick check to deal with common case of seeing the *same* price
		// broadcast from multiple peers simultaneously.
		if self.contains_price(price.hash()) {
			return Err(PoolError::DuplicatePrice);
		}

		// Make sure the transaction is valid before anything else.
		// Validate tx accounting for max tx weight.
		price
			.validate(self.verifier_cache.clone(), header.timestamp)
			.map_err(PoolError::InvalidPrice)?;

		// p2p broadcast this price
		self.peers().broadcast_price(&price);

		//        if let Err(e) = self.calculate_full_price_pairs(&rates) {
		//            warn!("price_encode failed: {:?}", e);
		//        } else {
		//            let serialized_price = self.encode_price_feeder(&prev_price_rates, &rates);
		//
		//            prev_price_rates = Some(rates.iter().map(|r| r.rate).collect());
		//            let decoded_diffs = diff0_decompress(serialized_price).unwrap();
		//            // convert i64 to float64 with 10^-9 precision
		//            let diffs: Vec<f64> = decoded_diffs
		//                .iter()
		//                .map(|r| *r as f64 / precision)
		//                .collect();
		//            debug!("deco price pairs = {:?}", diffs);
		//        }

		self.entries
			.sort_by(|a, b| a.date.partial_cmp(&b.date).unwrap());

		// only keep latest 5 minutes prices
		if self.total_size() > 5 * consensus::price_feeders_list().len() {
			self.evict_from_pool();
			return Err(PoolError::OverCapacity);
		}
		Ok(())
	}

	/// Get the total size of the pool.
	pub fn total_size(&self) -> usize {
		self.entries.len()
	}

	/// Remove the oldest prices.
	pub fn evict_from_pool(&mut self) {
		let oldest_date = self.entries.last().clone().unwrap().date;
		let count = self
			.entries
			.iter()
			.filter(|&p| p.date != oldest_date)
			.count();
		self.entries.truncate(count);
	}
}

/// Possible errors when interacting with the transaction pool.
#[derive(Debug, Fail, PartialEq)]
pub enum PoolError {
	/// An invalid pool entry caused by underlying tx validation error
	#[fail(display = "Invalid Price - {}", _0)]
	InvalidPrice(price::Error),
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

impl From<price::Error> for PoolError {
	fn from(e: price::Error) -> PoolError {
		PoolError::InvalidPrice(e)
	}
}
