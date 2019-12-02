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

use super::utils::w;
use crate::chain;
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::util;
use crate::util::secp::pedersen::Commitment;
use crate::web::*;
use enum_primitive::FromPrimitive;
use failure::ResultExt;
use gotts_core::core::{OutputFeatures, OutputIdentifier};
use hyper::{Body, Request, StatusCode};
use std::sync::Weak;

// Sum tree handler. Retrieve the roots:
// GET /v1/txhashset/roots
//
// Last inserted nodes::
// GET /v1/txhashset/lastoutputs (gets last 10)
// GET /v1/txhashset/lastoutputs?n=5
// GET /v1/txhashset/lastrangeproofs
// GET /v1/txhashset/lastkernels

// UTXO traversal::
// GET /v1/txhashset/outputs?start_index=1&max=100
// GET /v1/txhashset/nit-outputs?start_index=1&max=100
//
// Build a merkle proof for a given output commitment
// GET /v1/txhashset/merkleproof?id=xxx

pub struct TxHashSetHandler {
	pub chain: Weak<chain::Chain>,
}

impl TxHashSetHandler {
	// gets roots
	fn get_roots(&self) -> Result<TxHashSet, Error> {
		Ok(TxHashSet::from_head(w(&self.chain)?))
	}

	// gets last n outputs inserted in to the tree
	fn get_last_n_output(&self, distance: u64) -> Result<Vec<TxHashSetNode>, Error> {
		Ok(TxHashSetNode::get_last_n_output(w(&self.chain)?, distance))
	}

	// gets last n kernels inserted in to the tree
	fn get_last_n_kernel(&self, distance: u64) -> Result<Vec<TxHashSetNode>, Error> {
		Ok(TxHashSetNode::get_last_n_kernel(w(&self.chain)?, distance))
	}

	// allows traversal of utxo set
	fn outputs(&self, start_index: u64, mut max: u64) -> Result<OutputListing, Error> {
		//set a limit here
		if max > 10_000 {
			max = 10_000;
		}
		let chain = w(&self.chain)?;
		let outputs = chain
			.unspent_outputs_by_insertion_index(start_index, max)
			.context(ErrorKind::NotFound)?;
		let out = OutputListing {
			last_retrieved_index: outputs.0,
			highest_index: outputs.1,
			outputs: outputs
				.2
				.iter()
				.map(|x| OutputPrintable::from_output(x, chain.clone(), None, false))
				.collect::<Result<Vec<_>, _>>()
				.context(ErrorKind::Internal("cain error".to_owned()))?,
		};
		Ok(out)
	}

	// allows traversal of utxo set, non-interactive transaction outputs only.
	fn nit_outputs(&self, start_index: u64, mut max: u64) -> Result<OutputListing, Error> {
		//set a limit here
		if max > 10_000 {
			max = 10_000;
		}
		let chain = w(&self.chain)?;
		let outputs = chain
			.nit_unspent_outputs_by_insertion_index(start_index, max)
			.context(ErrorKind::NotFound)?;
		let out = OutputListing {
			last_retrieved_index: outputs.0,
			highest_index: outputs.1,
			outputs: outputs
				.2
				.iter()
				.map(|x| OutputPrintable::from_output(x, chain.clone(), None, false))
				.collect::<Result<Vec<_>, _>>()
				.context(ErrorKind::Internal("cain error".to_owned()))?,
		};
		Ok(out)
	}

	// return a dummy output with merkle proof for position filled out
	// (to avoid having to create a new type to pass around)
	fn get_merkle_proof_for_output(
		&self,
		id: &str,
		features: OutputFeatures,
	) -> Result<OutputPrintable, Error> {
		let c = util::from_hex(String::from(id)).context(ErrorKind::Argument(format!(
			"Not a valid commitment: {}",
			id
		)))?;
		let commit = Commitment::from_vec(c);
		let chain = w(&self.chain)?;
		let ofph = chain
			.get_output_pos_height(&commit)
			.context(ErrorKind::NotFound)?;
		let id = OutputIdentifier::new(features, &commit);
		let merkle_proof = chain
			.get_merkle_proof_for_output(&id)
			.map_err(|_| ErrorKind::NotFound)?;
		let output = chain
			.unspent_output_by_position(ofph.position, features)
			.ok_or(ErrorKind::NotFound)?;
		Ok(OutputPrintable {
			output,
			output_type: OutputType::Coinbase,
			spent: false,
			block_height: Some(ofph.height),
			merkle_proof: Some(merkle_proof),
			mmr_index: ofph.position,
		})
	}
}

impl Handler for TxHashSetHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		// TODO: probably need to set a reasonable max limit here
		let params = QueryParams::from(req.uri().query());
		let last_n = parse_param_no_err!(params, "n", 10);
		let start_index = parse_param_no_err!(params, "start_index", 1);
		let max = parse_param_no_err!(params, "max", 100);
		let id = parse_param_no_err!(params, "id", "".to_owned());
		let output_type = parse_param_no_err!(params, "type", 0u8);
		let features = OutputFeatures::from_u8(output_type).unwrap_or(OutputFeatures::Plain);

		match right_path_element!(req) {
			"roots" => result_to_response(self.get_roots()),
			"lastoutputs" => result_to_response(self.get_last_n_output(last_n)),
			"lastkernels" => result_to_response(self.get_last_n_kernel(last_n)),
			"outputs" => result_to_response(self.outputs(start_index, max)),
			"nit-outputs" => result_to_response(self.nit_outputs(start_index, max)),
			"merkleproof" => result_to_response(self.get_merkle_proof_for_output(&id, features)),
			_ => response(StatusCode::BAD_REQUEST, ""),
		}
	}
}
