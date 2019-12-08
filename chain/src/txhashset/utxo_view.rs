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

//! Lightweight readonly view into output MMR for convenience.

use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::pmmr::{self, ReadonlyPMMR};
use crate::core::core::{
	Block, BlockHeader, Input, Output, OutputEx, OutputFeatures, OutputI, OutputII, Transaction,
};
use crate::core::global;
use crate::core::ser::PMMRIndexHashable;
use crate::error::{Error, ErrorKind};
use crate::store::Batch;
use crate::util::secp::pedersen::Commitment;
use gotts_store::pmmr::PMMRBackend;
use std::collections::HashMap;

/// Readonly view of the UTXO set (based on output MMR).
pub struct UTXOView<'a> {
	//todo: make output_i_pmmr and output_ii_pmmr as a generic type
	output_i_pmmr: ReadonlyPMMR<'a, OutputI, PMMRBackend<OutputI>>,
	output_ii_pmmr: ReadonlyPMMR<'a, OutputII, PMMRBackend<OutputII>>,
	header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
	batch: &'a Batch<'a>,
}

impl<'a> UTXOView<'a> {
	/// Build a new UTXO view.
	pub fn new(
		output_i_pmmr: ReadonlyPMMR<'a, OutputI, PMMRBackend<OutputI>>,
		output_ii_pmmr: ReadonlyPMMR<'a, OutputII, PMMRBackend<OutputII>>,
		header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		batch: &'a Batch<'_>,
	) -> UTXOView<'a> {
		UTXOView {
			output_i_pmmr,
			output_ii_pmmr,
			header_pmmr,
			batch,
		}
	}

	/// Validate a block against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_block(&self, block: &Block) -> Result<(), Error> {
		for output in block.outputs() {
			self.validate_output(output)?;
		}

		let next_block_height = block.header.height + 1;
		for input in block.inputs() {
			self.validate_input(&input, next_block_height)?;
		}
		Ok(())
	}

	/// Validate a transaction against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_tx(&self, tx: &Transaction, next_block_height: u64) -> Result<(), Error> {
		let mut total_inputs_value = 0u64;
		let mut total_outputs_value = 0u64;

		for output in tx.outputs() {
			self.validate_output(output)?;
			total_outputs_value = total_outputs_value.saturating_add(output.value);
		}

		for input in tx.inputs() {
			let input_value = self.validate_input(&input, next_block_height)?;
			total_inputs_value = total_inputs_value.saturating_add(input_value);
		}

		if total_inputs_value != total_outputs_value.saturating_add(tx.overage()) {
			debug!(
				"validate_tx: {} sum validate fail. total inputs: {}, total outputs: {}, fee: {}",
				tx.hash(),
				total_inputs_value,
				total_outputs_value,
				tx.overage(),
			);
			return Err(ErrorKind::TransactionSumMismatch)?;
		}

		Ok(())
	}

	/// Given a vector of Input, return the corresponding Outputs full bodies.
	pub fn inputs_body(&self, inputs: &Vec<Input>) -> Result<Vec<Output>, Error> {
		let mut outputs: Vec<Output> = Vec::with_capacity(inputs.len());
		for input in inputs {
			if let Ok(ofph) = self.batch.get_output_pos_height(&input.commitment()) {
				match ofph.features {
					OutputFeatures::Plain | OutputFeatures::Coinbase => {
						if let Some(output) = self.output_i_pmmr.get_data(ofph.position) {
							if output.id.commit == input.commit {
								outputs.push(output.into_output());
								continue;
							}
						}
					}
					OutputFeatures::SigLocked => {
						if let Some(output) = self.output_ii_pmmr.get_data(ofph.position) {
							if output.id.commit == input.commit {
								outputs.push(output.into_output());
								continue;
							}
						}
					}
				}
			}
			return Err(ErrorKind::AlreadySpent(input.commitment()).into());
		}
		Ok(outputs)
	}

	// Input is valid if it is spending an (unspent) output
	// that currently exists in the output MMR.
	// Compare the hash in the output MMR at the expected pos.
	fn validate_input(&self, input: &Input, next_block_height: u64) -> Result<u64, Error> {
		if let Ok(ofph) = self.batch.get_output_pos_height(&input.commitment()) {
			match ofph.features {
				OutputFeatures::Plain | OutputFeatures::Coinbase => {
					if let Some(hash) = self.output_i_pmmr.get_hash(ofph.position) {
						if let Some(output) = self.output_i_pmmr.get_data(ofph.position) {
							if hash == output.hash_with_index(ofph.position - 1)
								&& output.id.commit == input.commit
							{
								return Ok(output.value);
							}
						}
					}
				}
				OutputFeatures::SigLocked => {
					if let Some(hash) = self.output_ii_pmmr.get_hash(ofph.position) {
						if let Some(output) = self.output_ii_pmmr.get_data(ofph.position) {
							if hash == output.hash_with_index(ofph.position - 1)
								&& output.id.commit == input.commit
							{
								// Find the "cutoff" height.
								let cutoff_height = next_block_height
									.checked_sub(output.locker.relative_lock_height as u64)
									.unwrap_or(0);

								// If input height exceed the cutoff_height
								// we know they have not yet sufficiently matured.
								if ofph.height > cutoff_height {
									return Err(ErrorKind::ImmatureCoinbase.into());
								} else {
									return Ok(output.value);
								}
							}
						}
					}
				}
			};
		}
		Err(ErrorKind::AlreadySpent(input.commitment()).into())
	}

	// Output is valid if it would not result in a duplicate commitment in the output MMR.
	fn validate_output(&self, output: &Output) -> Result<(), Error> {
		if let Ok(ofph) = self.batch.get_output_pos_height(&output.commitment()) {
			match ofph.features {
				OutputFeatures::Plain | OutputFeatures::Coinbase => {
					if let Some(out_mmr) = self.output_i_pmmr.get_data(ofph.position) {
						if out_mmr.id.commitment() == output.commitment() {
							return Err(ErrorKind::DuplicateCommitment(output.commitment()).into());
						}
					}
				}
				OutputFeatures::SigLocked => {
					if let Some(out_mmr) = self.output_ii_pmmr.get_data(ofph.position) {
						if out_mmr.id.commitment() == output.commitment() {
							return Err(ErrorKind::DuplicateCommitment(output.commitment()).into());
						}
					}
				}
			}
		}
		Ok(())
	}

	/// Find the complete input/s info, use chain database data according to inputs
	pub fn get_complete_inputs(
		&self,
		inputs: &Vec<Input>,
	) -> Result<HashMap<Commitment, OutputEx>, Error> {
		let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
		for input in inputs {
			if let Ok(ofph) = self.batch.get_output_pos_height(&input.commitment()) {
				let output = match ofph.features {
					OutputFeatures::Plain | OutputFeatures::Coinbase => self
						.output_i_pmmr
						.get_data(ofph.position)
						.ok_or(ErrorKind::AlreadySpent(input.commitment()))?
						.into_output(),
					OutputFeatures::SigLocked => self
						.output_ii_pmmr
						.get_data(ofph.position)
						.ok_or(ErrorKind::AlreadySpent(input.commitment()))?
						.into_output(),
				};
				if output.id().commitment() == input.commitment() {
					complete_inputs.insert(
						input.commitment().clone(),
						OutputEx {
							output,
							height: ofph.height,
							mmr_index: ofph.position,
						},
					);
				}
			}
		}
		Ok(complete_inputs)
	}

	/// Verify we are not attempting to spend any coinbase outputs
	/// that have not sufficiently matured.
	pub fn verify_coinbase_maturity(&self, inputs: &Vec<Input>, height: u64) -> Result<(), Error> {
		// Find the greatest output pos of any coinbase
		// outputs we are attempting to spend.
		let max_height = inputs
			.iter()
			.filter(|x| x.is_coinbase())
			.filter_map(|x| self.batch.get_output_height(&x.commitment()).ok())
			.max()
			.unwrap_or(0);

		if max_height > 0 {
			// If we have not yet reached 1,440 blocks then
			// we can fail immediately as coinbase cannot be mature.
			if height < global::coinbase_maturity() {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}

			// Find the "cutoff" height.
			let cutoff_height = height.checked_sub(global::coinbase_maturity()).unwrap_or(0);

			// If any input height exceed the cutoff_height
			// we know they have not yet sufficiently matured.
			if max_height > cutoff_height {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}
		}

		Ok(())
	}

	/// Get the header hash for the specified pos from the underlying MMR backend.
	fn get_header_hash(&self, pos: u64) -> Option<Hash> {
		self.header_pmmr.get_data(pos).map(|x| x.hash())
	}

	/// Get the header at the specified height based on the current state of the extension.
	/// Derives the MMR pos from the height (insertion index) and retrieves the header hash.
	/// Looks the header up in the db by hash.
	pub fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, Error> {
		let pos = pmmr::insertion_to_pmmr_index(height + 1);
		if let Some(hash) = self.get_header_hash(pos) {
			let header = self.batch.get_block_header(&hash)?;
			Ok(header)
		} else {
			Err(ErrorKind::Other(format!("get header by height")).into())
		}
	}
}
