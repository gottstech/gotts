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

use std::sync::{Arc, Weak};

use crate::chain::{self, SyncState};
use crate::common::types::PriceOracleServerConfig;
use crate::core::consensus;
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::id::{ShortId, ShortIdentifiable};
use crate::core::core::price::{ExchangeRates, PoolError};
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::BlockHeader;
use crate::p2p;
use crate::util::OneTime;
use crate::util::RwLock;
use chrono::prelude::{DateTime, Utc};
use chrono::Duration;

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

	/// Take pool prices with the chain head as previous, filtering and ordering them in a way that's
	/// appropriate to put in a mined block.
	pub fn prepare_mineable_prices(
		&self,
		timestamp: DateTime<Utc>,
	) -> Result<Vec<ExchangeRates>, PoolError> {
		// Get all the new prices, sort and remove duplicated prices from same source.
		// The prices timestamp is at least within 60 seconds.
		let mut mineable_prices: Vec<ExchangeRates> = self
			.entries
			.clone()
			.into_iter()
			.filter(|p| p.date + Duration::seconds(60) > timestamp)
			.collect();
		mineable_prices.sort_by(|a, b| a.date.partial_cmp(&b.date).unwrap());
		mineable_prices.dedup_by_key(|p| p.source_uid);

		// Select part of feeders
		assert!(mineable_prices.len() <= consensus::price_feeders_list().len());
		mineable_prices.sort_unstable();

		Ok(mineable_prices)
	}

	/// Query the price pool for all known prices based on price short_ids
	/// from the provided compact_block.
	/// Note: does not validate that we return the full set of required prices.
	/// The caller will need to validate that themselves.
	pub fn retrieve_prices(
		&self,
		hash: Hash,
		nonce: u64,
		kern_ids: &[ShortId],
	) -> (Vec<ExchangeRates>, Vec<ShortId>) {
		let mut prices = Vec::with_capacity(kern_ids.len());
		let mut found_ids = Vec::with_capacity(kern_ids.len());

		// Rehash all entries in the pool using short_ids based on provided hash and nonce.
		for p in &self.entries {
			// rehash each kernel to calculate the block specific short_id
			let short_id = p.short_id(&hash, nonce);
			if kern_ids.contains(&short_id) {
				prices.push(p.clone());
				found_ids.push(short_id);
			}
			if found_ids.len() == kern_ids.len() {
				break;
			}
		}
		prices.dedup();
		(
			prices,
			kern_ids
				.into_iter()
				.filter(|id| !found_ids.contains(id))
				.cloned()
				.collect(),
		)
	}
}
