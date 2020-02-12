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

//! The Committed trait and associated errors.

use crate::keychain;
use crate::keychain::BlindingFactor;

use crate::util::secp::key::SecretKey;
use crate::util::secp::pedersen::Commitment;
use crate::util::{secp, secp_static, static_secp_instance};
use failure::Fail;

/// Errors from summing and verifying kernel excesses via committed trait.
#[derive(Debug, Clone, PartialEq, Eq, Fail, Serialize, Deserialize)]
pub enum Error {
	/// Keychain related error.
	#[fail(display = "Keychain error {}", _0)]
	Keychain(keychain::Error),
	/// Secp related error.
	#[fail(display = "Secp error {}", _0)]
	Secp(secp::Error),
	/// Kernel sums do not equal output sums.
	#[fail(display = "Kernel sum mismatch")]
	KernelSumMismatch,
	/// Committed overage (fee or reward) is invalid
	#[fail(display = "Invalid value")]
	InvalidValue,
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

impl From<keychain::Error> for Error {
	fn from(e: keychain::Error) -> Error {
		Error::Keychain(e)
	}
}

/// Implemented by types that hold inputs and outputs (and kernels)
/// containing Pedersen commitments.
/// Handles the collection of the commitments as well as their
/// summing, taking potential explicit overages of fees into account.
pub trait Committed {
	/// Gather the kernel excesses and sum them.
	fn sum_kernel_excesses(&self) -> Result<Commitment, Error> {
		// then gather the kernel excess commitments
		let kernel_commits = self.kernels_committed();

		// sum the commitments
		let kernel_sum = sum_commits(kernel_commits, vec![])?;

		Ok(kernel_sum)
	}

	/// Gathers commitments and sum them.
	fn sum_commitments(&self) -> Result<Commitment, Error> {
		// gather the commitments
		let input_commits = self.inputs_committed();
		let output_commits = self.outputs_committed();

		sum_commits(output_commits, input_commits)
	}

	/// Vector of input commitments to verify.
	fn inputs_committed(&self) -> Vec<Commitment>;

	/// Vector of output commitments to verify.
	fn outputs_committed(&self) -> Vec<Commitment>;

	/// Vector of kernel excesses to verify.
	fn kernels_committed(&self) -> Vec<Commitment>;

	/// Verify the sum of the kernel excesses equals the
	/// sum of the outputs, taking into account the kernel_offset.
	fn verify_kernel_sums(&self) -> Result<(Commitment, Commitment), Error> {
		// Sum all input|output|overage commitments.
		let utxo_sum = self.sum_commitments()?;

		// Sum the kernel excesses accounting for the kernel offset.
		let kernel_sum = self.sum_kernel_excesses()?;

		if utxo_sum != kernel_sum {
			return Err(Error::KernelSumMismatch);
		}

		Ok((utxo_sum, kernel_sum))
	}
}

/// Utility to sum positive and negative commitments, eliminating zero values
pub fn sum_commits(
	mut positive: Vec<Commitment>,
	mut negative: Vec<Commitment>,
) -> Result<Commitment, Error> {
	let zero_commit = secp_static::commit_to_zero_value();
	positive.retain(|x| *x != zero_commit);
	negative.retain(|x| *x != zero_commit);
	let secp = static_secp_instance();
	let secp = secp.lock();
	Ok(secp.commit_sum(positive, negative)?)
}

/// Utility function to take sets of positive and negative kernel offsets as
/// blinding factors, convert them to private key filtering zero values and
/// summing all of them. Useful to build blocks.
pub fn sum_kernel_offsets(
	positive: Vec<BlindingFactor>,
	negative: Vec<BlindingFactor>,
) -> Result<BlindingFactor, Error> {
	let secp = static_secp_instance();
	let secp = secp.lock();
	let positive = to_secrets(positive);
	let negative = to_secrets(negative);

	if positive.is_empty() {
		Ok(BlindingFactor::zero())
	} else {
		let sum = secp.blind_sum(positive, negative)?;
		Ok(BlindingFactor::from_secret_key(sum))
	}
}

fn to_secrets(bf: Vec<BlindingFactor>) -> Vec<SecretKey> {
	bf.into_iter()
		.filter(|x| *x != BlindingFactor::zero())
		.filter_map(|x| x.secret_key().ok())
		.collect::<Vec<_>>()
}
