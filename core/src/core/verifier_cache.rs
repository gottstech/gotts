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

//! VerifierCache trait for batch verifying outputs and kernels.
//! We pass a "caching verifier" into the block validation processing with this.

use lru_cache::LruCache;

use crate::core::hash::{Hash, Hashed};
use crate::core::ExchangeRates;
use crate::core::{InputEx, TxKernel};

/// Verifier cache for caching expensive verification results.
/// Specifically the following -
///   * kernel signature verification
///   * InputUnlocker signature verification
pub trait VerifierCache: Sync + Send {
	/// Takes a vec of tx kernels and returns those kernels that have not yet been verified.
	fn filter_kernel_sig_unverified(&mut self, kernels: &[TxKernel]) -> Vec<TxKernel>;
	/// Adds a vec of tx kernels to the cache (used in conjunction with the the filter above).
	fn add_kernel_sig_verified(&mut self, kernels: &[TxKernel]);
	/// Takes a vec of InputEx and returns those InputEx that have not yet been verified.
	fn filter_unlocker_unverified(&mut self, inputs: &[InputEx]) -> Vec<InputEx>;
	/// Adds a vec of InputEx to the cache (used in conjunction with the the filter above).
	fn add_unlocker_verified(&mut self, inputs: &[InputEx]);
	/// Takes a vec of prices and returns those prices that have not yet been verified.
	fn filter_prices_sig_unverified(&mut self, prices: &[ExchangeRates]) -> Vec<ExchangeRates>;
	/// Adds a vec of prices to the cache (used in conjunction with the the filter above).
	fn add_prices_sig_verified(&mut self, prices: &[ExchangeRates]);
}

/// An implementation of verifier_cache using lru_cache.
/// Caches tx kernels by kernel hash.
/// Caches InputUnlocker by InputUnlocker hash (InputUnlocker are committed to separately).
pub struct LruVerifierCache {
	kernel_sig_verification_cache: LruCache<Hash, ()>,
	unlocker_verification_cache: LruCache<Hash, ()>,
	prices_sig_verification_cache: LruCache<Hash, ()>,
}

impl LruVerifierCache {
	/// TODO how big should these caches be?
	/// They need to be *at least* large enough to cover a maxed out block.
	pub fn new() -> LruVerifierCache {
		LruVerifierCache {
			kernel_sig_verification_cache: LruCache::new(50_000),
			unlocker_verification_cache: LruCache::new(50_000),
			prices_sig_verification_cache: LruCache::new(50_000),
		}
	}
}

impl VerifierCache for LruVerifierCache {
	fn filter_kernel_sig_unverified(&mut self, kernels: &[TxKernel]) -> Vec<TxKernel> {
		let res = kernels
			.iter()
			.filter(|x| !self.kernel_sig_verification_cache.contains_key(&x.hash()))
			.cloned()
			.collect::<Vec<_>>();
		trace!(
			"lru_verifier_cache: kernel sigs: {}, not cached (must verify): {}",
			kernels.len(),
			res.len()
		);
		res
	}

	fn add_kernel_sig_verified(&mut self, kernels: &[TxKernel]) {
		for k in kernels {
			self.kernel_sig_verification_cache.insert(k.hash(), ());
		}
	}

	fn filter_unlocker_unverified(&mut self, inputs: &[InputEx]) -> Vec<InputEx> {
		let res = inputs
			.iter()
			.filter(|x| !self.unlocker_verification_cache.contains_key(&x.hash()))
			.cloned()
			.collect::<Vec<_>>();
		trace!(
			"lru_verifier_cache: InputEx: {}, not cached (must verify): {}",
			inputs.len(),
			res.len()
		);
		res
	}

	fn add_unlocker_verified(&mut self, inputs: &[InputEx]) {
		for i in inputs {
			self.unlocker_verification_cache.insert(i.hash(), ());
		}
	}

	fn filter_prices_sig_unverified(&mut self, prices: &[ExchangeRates]) -> Vec<ExchangeRates> {
		let res = prices
			.iter()
			.filter(|x| !self.prices_sig_verification_cache.contains_key(&x.hash()))
			.cloned()
			.collect::<Vec<_>>();
		trace!(
			"lru_verifier_cache: prices sigs: {}, not cached (must verify): {}",
			prices.len(),
			res.len()
		);
		res
	}

	fn add_prices_sig_verified(&mut self, prices: &[ExchangeRates]) {
		for p in prices {
			self.prices_sig_verification_cache.insert(p.hash(), ());
		}
	}
}
