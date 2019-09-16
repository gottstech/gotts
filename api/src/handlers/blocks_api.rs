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
use super::utils::{get_output, w};
use crate::chain;
use crate::core::core::hash::Hash;
use crate::core::core::hash::Hashed;
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::util;
use crate::web::*;
use failure::ResultExt;
use hyper::{Body, Request, StatusCode};
use regex::Regex;
use std::sync::Weak;

/// Gets block headers given either a hash or height or an output commit.
/// GET /v1/headers/<hash>
/// GET /v1/headers/<height>
/// GET /v1/headers/<output commit>
///
pub struct HeaderHandler {
	pub chain: Weak<chain::Chain>,
}

impl HeaderHandler {
	fn get_header(&self, input: String) -> Result<BlockHeaderPrintable, Error> {
		// will fail quick if the provided isn't a commitment
		if let Ok(h) = self.get_header_for_output(input.clone()) {
			return Ok(h);
		}
		if let Ok(height) = input.parse() {
			match w(&self.chain)?.get_header_by_height(height) {
				Ok(header) => return Ok(BlockHeaderPrintable::from_header(&header)),
				Err(_) => return Err(ErrorKind::NotFound)?,
			}
		}
		check_block_param(&input)?;
		let vec = util::from_hex(input)
			.map_err(|e| ErrorKind::Argument(format!("invalid input: {}", e)))?;
		let h = Hash::from_vec(&vec);
		let header = w(&self.chain)?
			.get_block_header(&h)
			.context(ErrorKind::NotFound)?;
		Ok(BlockHeaderPrintable::from_header(&header))
	}

	fn get_header_for_output(&self, commit_id: String) -> Result<BlockHeaderPrintable, Error> {
		let oid = get_output(&self.chain, &commit_id)?.1;
		match w(&self.chain)?.get_header_for_output(&oid) {
			Ok(header) => Ok(BlockHeaderPrintable::from_header(&header)),
			Err(_) => Err(ErrorKind::NotFound)?,
		}
	}
}

impl Handler for HeaderHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		let el = right_path_element!(req);
		result_with_cuckoo_solution_to_response(self.get_header(el.to_string()))
	}
}

/// Gets block details given either a hash or an unspent commit
/// GET /v1/blocks/<hash>
/// GET /v1/blocks/<height>
/// GET /v1/blocks/<commit>
///
/// Optionally return results as "compact blocks" by passing "?compact" query
/// param GET /v1/blocks/<hash>?compact
///
/// Optionally turn off the Merkle proof extraction by passing "?no_merkle_proof" query
/// param GET /v1/blocks/<hash>?no_merkle_proof
pub struct BlockHandler {
	pub chain: Weak<chain::Chain>,
}

impl BlockHandler {
	fn get_block(&self, h: &Hash, include_merkle_proof: bool) -> Result<BlockPrintable, Error> {
		let chain = w(&self.chain)?;
		let block = chain.get_block(h).context(ErrorKind::NotFound)?;
		BlockPrintable::from_block(&block, chain, include_merkle_proof)
			.map_err(|_| ErrorKind::Internal("chain error".to_owned()).into())
	}

	fn get_compact_block(&self, h: &Hash) -> Result<CompactBlockPrintable, Error> {
		let chain = w(&self.chain)?;
		let block = chain.get_block(h).context(ErrorKind::NotFound)?;
		CompactBlockPrintable::from_compact_block(&block.into(), chain)
			.map_err(|_| ErrorKind::Internal("chain error".to_owned()).into())
	}

	// Try to decode the string as a height or a hash.
	fn parse_input(&self, input: String) -> Result<Hash, Error> {
		if let Ok(height) = input.parse() {
			match w(&self.chain)?.get_header_by_height(height) {
				Ok(header) => return Ok(header.hash()),
				Err(_) => return Err(ErrorKind::NotFound)?,
			}
		}
		check_block_param(&input)?;
		let vec = util::from_hex(input)
			.map_err(|e| ErrorKind::Argument(format!("invalid input: {}", e)))?;
		Ok(Hash::from_vec(&vec))
	}
}

fn check_block_param(input: &String) -> Result<(), Error> {
	lazy_static! {
		static ref RE: Regex = Regex::new(r"[0-9a-fA-F]{64}").unwrap();
	}
	if !RE.is_match(&input) {
		return Err(ErrorKind::Argument(
			"Not a valid hash or height.".to_owned(),
		))?;
	}
	Ok(())
}

impl Handler for BlockHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		let el = right_path_element!(req);
		let h = match self.parse_input(el.to_string()) {
			Err(e) => {
				return response(
					StatusCode::BAD_REQUEST,
					format!("failed to parse input: {}", e),
				);
			}
			Ok(h) => h,
		};

		let mut include_merkle_proof = true;
		if let Some(params) = req.uri().query() {
			let query = url::form_urlencoded::parse(params.as_bytes());
			let mut compact = false;
			for (param, _) in query {
				match param.as_ref() {
					"compact" => compact = true,
					"no_merkle_proof" => include_merkle_proof = false,
					_ => {
						return response(
							StatusCode::BAD_REQUEST,
							format!("unsupported query parameter: {}", param),
						)
					}
				}
			}

			if compact {
				return result_with_cuckoo_solution_to_response(self.get_compact_block(&h));
			}
		}
		result_with_cuckoo_solution_to_response(self.get_block(&h, include_merkle_proof))
	}
}
