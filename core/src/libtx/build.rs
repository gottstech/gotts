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

//! Utility functions to build Gotts transactions. Handles the blinding of
//! inputs and outputs, maintaining the sum of blinding factors, producing
//! the excess signature, etc.
//!
//! Each building function is a combinator that produces a function taking
//! a transaction a sum of blinding factors, to return another transaction
//! and sum. Combinators can then be chained and executed using the
//! _transaction_ function.
//!
//! Example:
//! build::transaction(vec![input_rand(75), output_rand(42), output_rand(32),
//!   with_fee(1)])

use crate::address::Address;
use crate::core::hash::{Hash, Hashed};
use crate::core::SINGLE_MSG_SIZE;
use crate::core::{
	Input, InputEx, InputUnlocker, Output, OutputFeatures, OutputFeaturesEx, Transaction, TxKernel,
};
use crate::keychain::{BlindSum, BlindingFactor, Identifier, Keychain};
use crate::libtx::proof::ProofBuild;
use crate::libtx::secp_ser;
use crate::libtx::{aggsig, proof, Error};
use crate::util::secp::{self, Commitment, Message, SecretKey};
use chrono::prelude::*;
use rand::{thread_rng, Rng};
use serde::{self, Deserialize};

/// Util structure for building the InputEx to spend an/some OutputII/s
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct InputExBuildParm {
	/// Transaction value
	pub value: u64,
	/// 'w' of the new Pedersen Commitment
	pub w: i64,
	/// Key ID
	pub key_id: Identifier,
	/// The ephemeral key for non-interactive transaction output
	#[serde(with = "secp_ser::seckey_serde")]
	pub ephemeral_key: SecretKey,
	/// The recipient's public key hash for non-interactive transaction output
	pub p2pkh: Hash,
}

impl InputExBuildParm {
	/// The msg signed as part of the Input with a signature.
	/// 	msg = hash(features || commit || value || timestamp) for single input
	/// 	msg = hash((features || commit || value) || (...) || timestamp) for multiple inputs
	/// Leave to caller to execute the final hash.
	pub fn msg_to_sign(&self, commit: &Commitment) -> Vec<u8> {
		let mut msg: Vec<u8> = Vec::with_capacity(SINGLE_MSG_SIZE);
		msg.push(OutputFeatures::SigLocked as u8);
		msg.extend_from_slice(commit.as_ref());
		msg.extend_from_slice(&self.value.to_be_bytes());
		msg
	}
}

/// Context information available to transaction combinators.
pub struct Context<'a, K, B>
where
	K: Keychain,
	B: ProofBuild,
{
	/// The keychain used for key derivation
	pub keychain: &'a K,
	/// The bulletproof builder
	pub builder: &'a B,
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum) pair into another, provided some context.
pub type Append<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	(Transaction, TxKernel, BlindSum),
) -> (Transaction, TxKernel, BlindSum);

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
fn build_input<K, B>(
	value: u64,
	w: i64,
	features: OutputFeatures,
	key_id: Identifier,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			let commit = build.keychain.commit(w, &key_id).unwrap();
			let input = Input::new(features, commit);
			(
				tx.with_input(input),
				kern,
				sum.sub_key_id(key_id.to_value_path(value, w)),
			)
		},
	)
}

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
pub fn input<K, B>(value: u64, w: i64, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!(
		"Building input (spending regular output): {}, {}",
		value, key_id
	);
	build_input(value, w, OutputFeatures::Plain, key_id)
}

/// Adds a coinbase input spending a coinbase output.
pub fn coinbase_input<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!("Building input (spending coinbase): {}, {}", value, key_id);
	build_input(value, 0i64, OutputFeatures::Coinbase, key_id)
}

/// Adds a SigLocked input with the provided value and blinding key to the transaction
/// being built.
pub fn siglocked_input<K, B>(input_build_parm: Vec<InputExBuildParm>) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	//todo: check the 'p2pkh' and 'key_id' is same for each element, and verify the 'p2pkh' with the key_id

	{
		let values: Vec<u64> = input_build_parm.iter().map(|i| i.value).collect();
		let keys: Vec<Identifier> = input_build_parm.iter().map(|i| i.key_id).collect();
		debug!(
			"Building SigLocked input (spending SigLocked output/s): {:?}, {:?}",
			values, keys,
		);
	}
	Box::new(
		move |build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			let mut inputs: Vec<Input> = Vec::with_capacity(input_build_parm.len());
			let mut msg_to_sign: Vec<u8> =
				Vec::with_capacity(input_build_parm.len() * SINGLE_MSG_SIZE);

			let key_id = input_build_parm[0].key_id.clone();
			let mut total_sum = sum;
			for parm in &input_build_parm {
				let commit = build
					.keychain
					.commit_raw(parm.w, &parm.ephemeral_key)
					.unwrap();
				msg_to_sign.extend_from_slice(&parm.msg_to_sign(&commit));
				inputs.push(Input::new(OutputFeatures::SigLocked, commit));
				total_sum = total_sum.sub_blinding_factor(BlindingFactor::from_secret_key(
					parm.ephemeral_key.clone(),
				));
			}
			let now = Utc::now();
			// Hashing to get the final msg for signature
			let hash = (msg_to_sign, now.timestamp()).hash();
			let msg = Message::from_slice(&hash.as_bytes()).unwrap();
			let pub_key = build.keychain.derive_pub_key(&key_id).unwrap();
			let sig = secp::aggsig::sign_single(
				build.keychain.secp(),
				&msg,
				&build.keychain.derive_key(&key_id).unwrap(),
				None,
				None,
				None,
				Some(&pub_key),
				None,
			)
			.unwrap();

			(
				tx.with_input_ex(InputEx::InputsWithUnlocker {
					inputs,
					unlocker: InputUnlocker {
						timestamp: now,
						sig,
						pub_key,
					},
				}),
				kern,
				total_sum,
			)
		},
	)
}

/// Adds an output with the provided value and key identifier from the keychain.
pub fn output<K, B>(value: u64, w: Option<i64>, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			let w: i64 = if let Some(w) = w {
				w
			} else {
				thread_rng().gen()
			};
			let commit = build.keychain.commit(w, &key_id).unwrap();

			debug!("Building output: {}, {:?}", value, commit);

			let spath =
				proof::create_secured_path(build.keychain, build.builder, w, &key_id, commit);

			(
				tx.with_output(Output {
					features: OutputFeaturesEx::Plain { spath },
					commit,
					value,
				}),
				kern,
				sum.add_key_id(key_id.to_value_path(value, w)),
			)
		},
	)
}

/// Adds a non-interactive transaction output with the provided value and key identifier from the keychain.
pub fn non_interactive_output<K, B>(
	value: u64,
	w: Option<i64>,
	recipient_address: Address,
	use_test_rng: bool,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			let w: i64 = if let Some(w) = w {
				w
			} else {
				thread_rng().gen()
			};

			let (commit, locker, ephemeral_key) = proof::create_output_locker(
				build.keychain,
				value,
				&recipient_address.get_inner_pubkey(),
				w,
				1,
				use_test_rng,
			)
			.unwrap();
			debug!(
				"Building non-interactive tx output: {}, {:?}",
				value, commit
			);

			(
				tx.with_output(Output {
					features: OutputFeaturesEx::SigLocked { locker },
					commit,
					value,
				}),
				kern,
				sum.add_blinding_factor(BlindingFactor::from_secret_key(ephemeral_key)),
			)
		},
	)
}

/// Sets the fee on the transaction being built.
pub fn with_fee<K, B>(fee: u64) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			(tx, kern.with_fee(fee), sum)
		},
	)
}

/// Sets the lock_height on the transaction being built.
pub fn with_lock_height<K, B>(lock_height: u64) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			(tx, kern.with_lock_height(lock_height), sum)
		},
	)
}

/// Adds a known excess value on the transaction being built. Usually used in
/// combination with the initial_tx function when a new transaction is built
/// by adding to a pre-existing one.
pub fn with_excess<K, B>(excess: BlindingFactor) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, (tx, kern, sum)| -> (Transaction, TxKernel, BlindSum) {
			(tx, kern, sum.add_blinding_factor(excess.clone()))
		},
	)
}

/// Sets an initial transaction to add to when building a new transaction.
/// We currently only support building a tx with a single kernel with
/// build::transaction()
pub fn initial_tx<K, B>(mut tx: Transaction) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	assert_eq!(tx.kernels().len(), 1);
	let kern = tx.kernels_mut().remove(0);
	Box::new(
		move |_build, (_, _, sum)| -> (Transaction, TxKernel, BlindSum) {
			(tx.clone(), kern.clone(), sum)
		},
	)
}

/// Builds a new transaction by combining all the combinators provided in a
/// Vector. Transactions can either be built "from scratch" with a list of
/// inputs or outputs or from a pre-existing transaction that gets added to.
///
/// Example:
/// let (tx1, sum) = build::transaction(vec![input_rand(4), output_rand(1),
///   with_fee(1)], keychain).unwrap();
/// let (tx2, _) = build::transaction(vec![initial_tx(tx1), with_excess(sum),
///   output_rand(2)], keychain).unwrap();
///
pub fn partial_transaction<K, B>(
	elems: Vec<Box<Append<K, B>>>,
	keychain: &K,
	builder: &B,
) -> Result<(Transaction, BlindingFactor), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, kern, sum) = elems.iter().fold(
		(Transaction::empty(), TxKernel::empty(), BlindSum::new()),
		|acc, elem| elem(&mut ctx, acc),
	);
	let blind_sum = ctx.keychain.blind_sum(&sum)?;

	// we only support building a tx with a single kernel via build::transaction()
	assert!(tx.kernels().is_empty());

	let tx = tx.with_kernel(kern);

	Ok((tx, blind_sum))
}

/// Builds a complete transaction.
pub fn transaction<K, B>(
	elems: Vec<Box<Append<K, B>>>,
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, mut kern, sum) = elems.iter().fold(
		(Transaction::empty(), TxKernel::empty(), BlindSum::new()),
		|acc, elem| elem(&mut ctx, acc),
	);
	let blind_sum = ctx.keychain.blind_sum(&sum)?;

	// Construct the message to be signed.
	let msg = kern.msg_to_sign()?;

	// Generate kernel excess and excess_sig using the split key k1.
	let skey = blind_sum.secret_key()?;
	kern.excess = ctx.keychain.secp().commit_i(0i64, &skey)?;
	let pubkey = &kern.excess.to_pubkey(&keychain.secp())?;
	kern.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &blind_sum, Some(&pubkey)).unwrap();

	// Set the kernel on the tx (assert this is now a single-kernel tx).
	assert!(tx.kernels().is_empty());
	let tx = tx.with_kernel(kern);
	assert_eq!(tx.kernels().len(), 1);

	Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {
	use crate::util::secp::pedersen::Commitment;
	use crate::util::RwLock;
	use std::collections::HashMap;
	use std::sync::Arc;

	use super::*;
	use crate::core::transaction::{OutputEx, Weighting};
	use crate::core::verifier_cache::{LruVerifierCache, VerifierCache};
	use crate::keychain::{ExtKeychain, ExtKeychainPath};
	use crate::libtx::ProofBuilder;

	fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
		Arc::new(RwLock::new(LruVerifierCache::new()))
	}

	#[test]
	fn blind_simple_tx() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain, &Identifier::zero());
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
		let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

		let vc = verifier_cache();

		let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
		let (pre_tx, _) = partial_transaction(
			vec![
				output(10, Some(0i64), key_id1),
				output(12, Some(0i64), key_id2),
			],
			&keychain,
			&builder,
		)
		.unwrap();
		complete_inputs.insert(
			pre_tx.body.outputs[0].commit,
			OutputEx {
				output: pre_tx.body.outputs[0],
				height: 0,
				mmr_index: 1,
			},
		);
		complete_inputs.insert(
			pre_tx.body.outputs[1].commit,
			OutputEx {
				output: pre_tx.body.outputs[1],
				height: 0,
				mmr_index: 2,
			},
		);

		let tx = transaction(
			vec![
				input(10, 0i64, key_id1),
				input(12, 0i64, key_id2),
				output(20, Some(0i64), key_id3),
				with_fee(2),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(
			Weighting::AsTransaction,
			vc.clone(),
			Some(&complete_inputs),
			1,
		)
		.unwrap();
	}

	#[test]
	fn blind_simpler_tx() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain, &Identifier::zero());
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();

		let vc = verifier_cache();

		let mut complete_inputs: HashMap<Commitment, OutputEx> = HashMap::new();
		let (pre_tx, _) =
			partial_transaction(vec![output(6, Some(0i64), key_id1)], &keychain, &builder).unwrap();
		complete_inputs.insert(
			pre_tx.body.outputs[0].commit,
			OutputEx {
				output: pre_tx.body.outputs[0],
				height: 0,
				mmr_index: 1,
			},
		);

		let tx = transaction(
			vec![
				input(6, 0i64, key_id1),
				output(2, Some(0i64), key_id2),
				with_fee(4),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(
			Weighting::AsTransaction,
			vc.clone(),
			Some(&complete_inputs),
			1,
		)
		.unwrap();
	}
}
