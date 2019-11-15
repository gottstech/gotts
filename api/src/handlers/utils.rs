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

use crate::chain;
use crate::core::core::{OutputEx, OutputIdentifier};
use crate::rest::*;
use crate::util;
use crate::util::secp::pedersen::Commitment;
use failure::ResultExt;
use std::sync::{Arc, Weak};

// All handlers use `Weak` references instead of `Arc` to avoid cycles that
// can never be destroyed. These 2 functions are simple helpers to reduce the
// boilerplate of dealing with `Weak`.
pub fn w<T>(weak: &Weak<T>) -> Result<Arc<T>, Error> {
	weak.upgrade()
		.ok_or_else(|| ErrorKind::Internal("failed to upgrade weak refernce".to_owned()).into())
}

/// Retrieves an output from the chain given a commit id (a tiny bit iteratively)
pub fn get_output(
	chain: &Weak<chain::Chain>,
	id: &str,
) -> Result<(OutputEx, OutputIdentifier), Error> {
	let c = util::from_hex(String::from(id)).context(ErrorKind::Argument(format!(
		"Not a valid commitment: {}",
		id
	)))?;
	let commit = Commitment::from_vec(c);

	let chain = w(chain)?;
	{
		let res = chain.is_unspent(&commit);
		match res {
			Ok(output_pos) => {
				if let Some(out) =
					chain.unspent_output_by_position(output_pos.position, output_pos.features)
				{
					return Ok((
						OutputEx {
							output: out.clone(),
							height: output_pos.height,
							mmr_index: output_pos.position,
						},
						out.id(),
					));
				} else {
					error!(
						"get_output: err: corrupted storage? unspent output not found in pmmr backend. for commit: {:?}",
						commit,
					);
					return Err(ErrorKind::NotFound)?;
				}
			}
			Err(e) => {
				trace!(
					"get_output: err: {} for commit: {:?}",
					e.to_string(),
					commit,
				);
			}
		}
	}
	Err(ErrorKind::NotFound)?
}
