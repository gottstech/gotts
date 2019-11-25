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

//! Transactions

use crate::blake2::blake2b::blake2b;
use crate::core::hash::{DefaultHashable, Hash, Hashed};
use crate::core::verifier_cache::VerifierCache;
use crate::core::{committed, Committed};
use crate::keychain::{self};
use crate::libtx::proof::{
	OutputLocker, PathMessage, SecuredPath, OUTPUT_LOCKER_SIZE, SECURED_PATH_SIZE,
};
use crate::libtx::secp_ser;
use crate::ser::{
	self, read_multi, FixedLength, PMMRIndexHashable, PMMRable, Readable, Reader,
	VerifySortedAndUnique, Writeable, Writer,
};
use crate::util;
use crate::util::secp;
use crate::util::secp::pedersen::Commitment;
use crate::util::static_secp_instance;
use crate::util::RwLock;
use crate::{consensus, global};

use chrono::naive::{MAX_DATE, MIN_DATE};
use chrono::prelude::{DateTime, NaiveDateTime, Utc};
use enum_primitive::FromPrimitive;
use std::cmp::Ordering;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::sync::Arc;
use std::u32;
use std::{error, fmt};

/// Single output message size. (features || commit || value)
pub const SINGLE_MSG_SIZE: usize = 1 + secp::PEDERSEN_COMMITMENT_SIZE + 8;

/// Various tx kernel variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelFeatures {
	/// Plain kernel (the default for Gotts txs).
	Plain {
		/// Plain kernels have fees.
		fee: u64,
	},
	/// A coinbase kernel.
	Coinbase,
	/// A kernel with an explicit lock height (and fee).
	HeightLocked {
		/// Height locked kernels have fees.
		fee: u64,
		/// Height locked kernels have lock heights.
		lock_height: u64,
	},
}

impl KernelFeatures {
	const PLAIN_U8: u8 = 0;
	const COINBASE_U8: u8 = 1;
	const HEIGHT_LOCKED_U8: u8 = 2;

	/// Underlying (u8) value representing this kernel variant.
	/// This is the first byte when we serialize/deserialize the kernel features.
	pub fn as_u8(&self) -> u8 {
		match self {
			KernelFeatures::Plain { .. } => KernelFeatures::PLAIN_U8,
			KernelFeatures::Coinbase => KernelFeatures::COINBASE_U8,
			KernelFeatures::HeightLocked { .. } => KernelFeatures::HEIGHT_LOCKED_U8,
		}
	}

	/// Conversion for backward compatibility.
	pub fn as_string(&self) -> String {
		match self {
			KernelFeatures::Plain { .. } => String::from("Plain"),
			KernelFeatures::Coinbase => String::from("Coinbase"),
			KernelFeatures::HeightLocked { .. } => String::from("HeightLocked"),
		}
	}

	/// msg = hash(features)                       for coinbase kernels
	///       hash(features || fee)                for plain kernels
	///       hash(features || fee || lock_height) for height locked kernels
	pub fn kernel_sig_msg(&self) -> Result<secp::Message, Error> {
		let x = self.as_u8();
		let hash = match self {
			KernelFeatures::Plain { fee } => (x, fee).hash(),
			KernelFeatures::Coinbase => (x).hash(),
			KernelFeatures::HeightLocked { fee, lock_height } => (x, fee, lock_height).hash(),
		};

		let msg = secp::Message::from_slice(&hash.as_bytes())?;
		Ok(msg)
	}
}

impl Writeable for KernelFeatures {
	/// Protocol version v1 serialization.
	/// fee and lock_height could be skipped, depending on feature variants.
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			KernelFeatures::Plain { fee } => {
				writer.write_u8(self.as_u8())?;
				writer.write_u64(*fee)?;
			}
			KernelFeatures::Coinbase => {
				writer.write_u8(self.as_u8())?;
			}
			KernelFeatures::HeightLocked { fee, lock_height } => {
				writer.write_u8(self.as_u8())?;
				writer.write_u64(*fee)?;
				writer.write_u64(*lock_height)?;
			}
		}
		Ok(())
	}
}

impl Readable for KernelFeatures {
	/// Still only supporting protocol version v1 serialization.
	/// Always read both fee and lock_height, regardless of feature variant.
	/// These will be 0 values if not applicable, but bytes must still be read and verified.
	fn read(reader: &mut dyn Reader) -> Result<KernelFeatures, ser::Error> {
		let features = match reader.read_u8()? {
			KernelFeatures::PLAIN_U8 => {
				let fee = reader.read_u64()?;
				KernelFeatures::Plain { fee }
			}
			KernelFeatures::COINBASE_U8 => KernelFeatures::Coinbase,
			KernelFeatures::HEIGHT_LOCKED_U8 => {
				let fee = reader.read_u64()?;
				let lock_height = reader.read_u64()?;
				KernelFeatures::HeightLocked { fee, lock_height }
			}
			_ => {
				return Err(ser::Error::CorruptedData);
			}
		};
		Ok(features)
	}
}

/// Errors thrown by Transaction validation
#[derive(Clone, Eq, Debug, PartialEq, Serialize, Deserialize)]
pub enum Error {
	/// Underlying Secp256k1 error (signature validation or invalid public key
	/// typically)
	Secp(secp::Error),
	/// Underlying keychain related error
	Keychain(keychain::Error),
	/// The sum of output minus input commitments does not
	/// match the sum of kernel commitments
	KernelSumMismatch,
	/// Transaction public value sums do not match.
	TransactionSumMismatch,
	/// Restrict tx total weight.
	TooHeavy,
	/// Error originating from an invalid lock-height
	LockHeight(u64),
	/// Range proof validation error
	RangeProof,
	/// Error originating from an invalid Merkle proof
	MerkleProof,
	/// Returns if the value hidden within the a RangeProof message isn't
	/// repeated 3 times, indicating it's incorrect
	InvalidProofMessage,
	/// Error when verifying kernel sums via committed trait.
	Committed(committed::Error),
	/// Error when sums do not verify correctly during tx aggregation.
	/// Likely a "double spend" across two unconfirmed txs.
	AggregationError,
	/// Validation error relating to cut-through (tx is spending its own
	/// output).
	CutThrough,
	/// Validation error relating to output features.
	/// It is invalid for a transaction to contain a coinbase output, for example.
	InvalidOutputFeatures,
	/// Validation error relating to kernel features.
	/// It is invalid for a transaction to contain a coinbase kernel, for example.
	InvalidKernelFeatures,
	/// Validation error relating to input signature message.
	InvalidInputSigMsg,
	/// TxKernel Signature verification error.
	IncorrectSignature,
	/// InputUnlocker Signature verification error.
	UnlockerIncorrectSignature,
	/// Signature verification error, public key hash not match.
	IncorrectPubkey,
	/// Input does not exist among UTXO sets.
	InputNotExist,
	/// Spend time is earlier than output timestamp.
	IncorrectTimestamp,
	/// Underlying serialization error.
	Serialization(ser::Error),
	/// SecuredPath error.
	SecuredPath(String),
	/// OutputLocker error.
	OutputLocker(String),
	/// InputUnlocker error.
	InputUnlocker(String),
}

impl error::Error for Error {
	fn description(&self) -> &str {
		match *self {
			_ => "some kind of keychain error",
		}
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			_ => write!(f, "some kind of keychain error"),
		}
	}
}

impl From<ser::Error> for Error {
	fn from(e: ser::Error) -> Error {
		Error::Serialization(e)
	}
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

impl From<committed::Error> for Error {
	fn from(e: committed::Error) -> Error {
		Error::Committed(e)
	}
}

/// A proof that a transaction sums to zero. Includes both the transaction's
/// Pedersen commitment and the signature, that guarantees that the commitments
/// amount to zero.
/// The signature signs the fee and the lock_height, which are retained for
/// signature validation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernel {
	/// Options for a kernel's structure or use
	pub features: KernelFeatures,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key (sum of the commitment public keys).
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	pub excess_sig: secp::Signature,
}

impl DefaultHashable for TxKernel {}
hashable_ord!(TxKernel);

impl ::std::hash::Hash for TxKernel {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

impl Writeable for TxKernel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// We have access to the protocol version here.
		// This may be a protocol version based on a peer connection
		// or the version used locally for db storage.
		// We can handle version specific serialization here.
		let _version = writer.protocol_version();

		self.features.write(writer)?;
		self.excess.write(writer)?;
		self.excess_sig.write(writer)?;
		Ok(())
	}
}

impl Readable for TxKernel {
	fn read(reader: &mut dyn Reader) -> Result<TxKernel, ser::Error> {
		// We have access to the protocol version here.
		// This may be a protocol version based on a peer connection
		// or the version used locally for db storage.
		// We can handle version specific deserialization here.
		let _version = reader.protocol_version();

		Ok(TxKernel {
			features: KernelFeatures::read(reader)?,
			excess: Commitment::read(reader)?,
			excess_sig: secp::Signature::read(reader)?,
		})
	}
}

/// We store TxKernel in the kernel MMR.
/// Note: These are "variable size" to support different kernel feature variants.
impl PMMRable for TxKernel {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

/// Kernels are "variable size" but we need to implement FixedLength for legacy reasons.
/// The different length for 3 types: Plain, Coinbase, HeightLocked:
/// 	106/98/114=(9/1/17)+33+64.
/// At some point we will refactor the MMR backend so this is no longer required.
impl FixedLength for TxKernel {
	const LEN: usize = 0;
}

impl PMMRIndexHashable for TxKernel {
	fn hash_with_index(&self, index: u64) -> Hash {
		(index, self).hash()
	}
}

impl KernelFeatures {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		match self {
			KernelFeatures::Coinbase => true,
			_ => false,
		}
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		match self {
			KernelFeatures::Plain { .. } => true,
			_ => false,
		}
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		match self {
			KernelFeatures::HeightLocked { .. } => true,
			_ => false,
		}
	}
}

impl TxKernel {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		self.features.is_height_locked()
	}

	/// Return the excess commitment for this tx_kernel.
	pub fn excess(&self) -> Commitment {
		self.excess
	}

	/// Return the transaction fee for this tx_kernel.
	pub fn fee(&self) -> u64 {
		match self.features {
			KernelFeatures::Plain { fee } => fee,
			KernelFeatures::Coinbase => 0,
			KernelFeatures::HeightLocked { fee, .. } => fee,
		}
	}

	/// The msg signed as part of the tx kernel.
	/// Based on kernel features and associated fields (fee and lock_height).
	pub fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self.features.kernel_sig_msg()?;
		Ok(msg)
	}

	/// Verify the transaction proof validity. Entails handling the commitment
	/// as a public key and checking the signature verifies with the fee as
	/// message.
	pub fn verify(&self) -> Result<(), Error> {
		let secp = static_secp_instance();
		let secp = secp.lock();
		let sig = &self.excess_sig;
		// Verify aggsig directly in libsecp
		let pubkey = &self.excess.to_pubkey(&secp)?;
		if !secp::aggsig::verify_single(
			&secp,
			&sig,
			&self.msg_to_sign()?,
			None,
			&pubkey,
			Some(&pubkey),
			None,
			false,
		) {
			return Err(Error::IncorrectSignature);
		}
		Ok(())
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(tx_kernels: &Vec<TxKernel>) -> Result<(), Error> {
		let len = tx_kernels.len();
		let mut sigs: Vec<secp::Signature> = Vec::with_capacity(len);
		let mut pubkeys: Vec<secp::key::PublicKey> = Vec::with_capacity(len);
		let mut msgs: Vec<secp::Message> = Vec::with_capacity(len);

		let secp = static_secp_instance();
		let secp = secp.lock();

		for tx_kernel in tx_kernels {
			sigs.push(tx_kernel.excess_sig);
			pubkeys.push(tx_kernel.excess.to_pubkey(&secp)?);
			msgs.push(tx_kernel.msg_to_sign()?);
		}

		if !secp::aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}

	/// Build an empty tx kernel with zero values.
	pub fn empty() -> TxKernel {
		TxKernel {
			features: KernelFeatures::Plain { fee: 0 },
			excess: Commitment::from_vec(vec![0; 33]),
			excess_sig: secp::Signature::from_raw_data(&[0; 64]).unwrap(),
		}
	}

	/// Builds a new tx kernel with the provided fee.
	/// Will panic if we cannot safely do this on the existing kernel.
	/// i.e. Do not try and set a fee on a coinbase kernel.
	pub fn with_fee(self, fee: u64) -> TxKernel {
		match self.features {
			KernelFeatures::Plain { .. } => {
				let features = KernelFeatures::Plain { fee };
				TxKernel { features, ..self }
			}
			KernelFeatures::HeightLocked { lock_height, .. } => {
				let features = KernelFeatures::HeightLocked { fee, lock_height };
				TxKernel { features, ..self }
			}
			KernelFeatures::Coinbase => panic!("fee not supported on coinbase kernel"),
		}
	}

	/// Builds a new tx kernel with the provided lock_height.
	/// Will panic if we cannot safely do this on the existing kernel.
	/// i.e. Do not try and set a lock_height on a coinbase kernel.
	pub fn with_lock_height(self, lock_height: u64) -> TxKernel {
		match self.features {
			KernelFeatures::Plain { fee } | KernelFeatures::HeightLocked { fee, .. } => {
				let features = KernelFeatures::HeightLocked { fee, lock_height };
				TxKernel { features, ..self }
			}
			KernelFeatures::Coinbase => panic!("lock_height not supported on coinbase kernel"),
		}
	}
}

/// Wrapper around a tx kernel used when querying them by API.
/// These will be useful when we verify a transaction by its kernel excess.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernelApiEntry {
	/// The block height where this transaction is packaged into a block.
	pub height: u64,
	/// The underlying tx kernel.
	pub kernel: TxKernel,
}

/// Enum of possible tx weight verification options -
///
/// * As "transaction" checks tx (as block) weight does not exceed max_block_weight.
/// * As "block" same as above but allow for additional coinbase reward (1 output, 1 kernel).
/// * With "no limit" to skip the weight check.
///
#[derive(Clone, Copy)]
pub enum Weighting {
	/// Tx represents a tx (max block weight, accounting for additional coinbase reward).
	AsTransaction,
	/// Tx representing a tx with artificially limited max_weight.
	/// This is used when selecting mineable txs from the pool.
	AsLimitedTransaction(usize),
	/// Tx represents a block (max block weight).
	AsBlock,
	/// No max weight limit (skip the weight check).
	NoLimit,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBody {
	/// List of inputs by the transaction.
	pub inputs: Vec<InputEx>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<Output>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernel>,
}

/// PartialEq
impl PartialEq for TransactionBody {
	fn eq(&self, l: &TransactionBody) -> bool {
		self.inputs == l.inputs && self.outputs == l.outputs && self.kernels == l.kernels
	}
}

/// Implementation of Writeable for a body, defines how to
/// write the body as binary.
impl Writeable for TransactionBody {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(
			writer,
			[write_u32, self.inputs.len() as u32],
			[write_u32, self.outputs.len() as u32],
			[write_u32, self.kernels.len() as u32]
		);

		self.inputs.write(writer)?;
		self.outputs.write(writer)?;
		self.kernels.write(writer)?;

		Ok(())
	}
}

/// Implementation of Readable for a body, defines how to read a
/// body from a binary stream.
impl Readable for TransactionBody {
	fn read(reader: &mut dyn Reader) -> Result<TransactionBody, ser::Error> {
		let (input_len, output_len, kernel_len) =
			ser_multiread!(reader, read_u32, read_u32, read_u32);

		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		let tx_block_weight = TransactionBody::weight_as_block(
			input_len as usize,
			output_len as usize,
			kernel_len as usize,
		);

		if tx_block_weight > global::max_block_weight() {
			return Err(ser::Error::TooLargeReadErr);
		}

		let inputs = read_multi(reader, input_len as u64)?;
		let outputs = read_multi(reader, output_len as u64)?;
		let kernels = read_multi(reader, kernel_len as u64)?;

		// Initialize tx body and verify everything is sorted.
		let body = TransactionBody::init(inputs, outputs, kernels, true)
			.map_err(|_| ser::Error::CorruptedData)?;

		Ok(body)
	}
}

impl Committed for TransactionBody {
	fn inputs_committed(&self) -> Vec<Commitment> {
		let mut result: Vec<Commitment> = vec![];
		for inputs in &self.inputs {
			result.extend_from_slice(&inputs.commitments());
		}
		result
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.outputs.iter().map(|x| x.commitment()).collect()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.kernels.iter().map(|x| x.excess()).collect()
	}
}

impl Default for TransactionBody {
	fn default() -> TransactionBody {
		TransactionBody::empty()
	}
}

impl TransactionBody {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> TransactionBody {
		TransactionBody {
			inputs: vec![],
			outputs: vec![],
			kernels: vec![],
		}
	}

	/// Get the Inputs number
	pub fn get_inputs_number(&self) -> usize {
		self.inputs
			.iter()
			.fold(0usize, |t, inputs| t + inputs.len())
	}

	/// Get inputs
	pub fn inputs(&self) -> Vec<Input> {
		let total = self.get_inputs_number();
		let mut inputs: Vec<Input> = Vec::with_capacity(total);
		for input_ex in &self.inputs {
			inputs.extend_from_slice(&input_ex.inputs());
		}
		inputs
	}

	/// Sort the inputs|outputs|kernels.
	pub fn sort(&mut self) {
		self.inputs.sort_unstable();
		self.outputs.sort_unstable();
		self.kernels.sort_unstable();
	}

	/// Creates a new transaction body initialized with
	/// the provided inputs, outputs and kernels.
	/// Guarantees inputs, outputs, kernels are sorted lexicographically.
	pub fn init(
		inputs: Vec<InputEx>,
		outputs: Vec<Output>,
		kernels: Vec<TxKernel>,
		verify_sorted: bool,
	) -> Result<TransactionBody, Error> {
		let mut body = TransactionBody {
			inputs,
			outputs,
			kernels,
		};

		if verify_sorted {
			// If we are verifying sort order then verify and
			// return an error if not sorted lexicographically.
			body.verify_sorted()?;
		} else {
			// If we are not verifying sort order then sort in place and return.
			body.sort();
		}
		Ok(body)
	}

	/// Builds a new body with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(mut self, input: Input) -> TransactionBody {
		let input_ex = input.to_input_ex();
		self.inputs
			.binary_search(&input_ex)
			.err()
			.map(|e| self.inputs.insert(e, input_ex));

		self
	}

	/// Same as above but with an InputEx.
	pub fn with_input_ex(mut self, input_ex: InputEx) -> TransactionBody {
		self.inputs
			.binary_search(&input_ex)
			.err()
			.map(|e| self.inputs.insert(e, input_ex));
		self
	}

	/// Builds a new TransactionBody with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(mut self, output: Output) -> TransactionBody {
		self.outputs
			.binary_search(&output)
			.err()
			.map(|e| self.outputs.insert(e, output));
		self
	}

	/// Builds a new TransactionBody with the provided outputs added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_outputs(mut self, outputs: Vec<Output>) -> TransactionBody {
		for output in outputs {
			self.outputs
				.binary_search(&output)
				.err()
				.map(|e| self.outputs.insert(e, output));
		}
		self
	}

	/// Builds a new TransactionBody with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(mut self, kernel: TxKernel) -> TransactionBody {
		self.kernels
			.binary_search(&kernel)
			.err()
			.map(|e| self.kernels.insert(e, kernel));
		self
	}

	/// Total fee for a TransactionBody is the sum of fees of all fee carrying kernels.
	pub fn fee(&self) -> u64 {
		self.kernels
			.iter()
			.fold(0, |acc, k| acc.saturating_add(k.fee()))
	}

	fn overage(&self) -> i64 {
		self.fee() as i64
	}

	/// Calculate transaction weight
	pub fn body_weight(&self) -> usize {
		TransactionBody::weight(self.inputs.len(), self.outputs.len(), self.kernels.len())
	}

	/// Calculate weight of transaction using block weighing
	pub fn body_weight_as_block(&self) -> usize {
		TransactionBody::weight_as_block(self.inputs.len(), self.outputs.len(), self.kernels.len())
	}

	/// Calculate transaction weight from transaction details. This is non
	/// consensus critical and compared to block weight, incentivizes spending
	/// more outputs (to lower the fee).
	pub fn weight(input_len: usize, output_len: usize, kernel_len: usize) -> usize {
		let body_weight = output_len
			.saturating_mul(4)
			.saturating_add(kernel_len)
			.saturating_sub(input_len);
		max(body_weight, 1)
	}

	/// Calculate transaction weight using block weighing from transaction
	/// details. Consensus critical and uses consensus weight values.
	pub fn weight_as_block(input_len: usize, output_len: usize, kernel_len: usize) -> usize {
		input_len
			.saturating_mul(consensus::BLOCK_INPUT_WEIGHT)
			.saturating_add(output_len.saturating_mul(consensus::BLOCK_OUTPUT_WEIGHT))
			.saturating_add(kernel_len.saturating_mul(consensus::BLOCK_KERNEL_WEIGHT))
	}

	/// Lock height of a body is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.kernels
			.iter()
			.filter_map(|x| match x.features {
				KernelFeatures::HeightLocked { lock_height, .. } => Some(lock_height),
				_ => None,
			})
			.max()
			.unwrap_or(0)
	}

	/// Verify the body is not too big in terms of number of inputs|outputs|kernels.
	/// Weight rules vary depending on the "weight type" (block or tx or pool).
	fn verify_weight(&self, weighting: Weighting) -> Result<(), Error> {
		// A coinbase reward is a single output and a single kernel (for now).
		// We need to account for this when verifying max tx weights.
		let coinbase_weight = consensus::BLOCK_OUTPUT_WEIGHT + consensus::BLOCK_KERNEL_WEIGHT;

		// If "tx" body then remember to reduce the max_block_weight by the weight of a kernel.
		// If "limited tx" then compare against the provided max_weight.
		// If "block" body then verify weight based on full set of inputs|outputs|kernels.
		// If "pool" body then skip weight verification (pool can be larger than single block).
		//
		// Note: Taking a max tx and building a block from it we need to allow room
		// for the additional coinbase reward (1 output + 1 kernel).
		//
		let max_weight = match weighting {
			Weighting::AsTransaction => global::max_block_weight().saturating_sub(coinbase_weight),
			Weighting::AsLimitedTransaction(max_weight) => {
				min(global::max_block_weight(), max_weight).saturating_sub(coinbase_weight)
			}
			Weighting::AsBlock => global::max_block_weight(),
			Weighting::NoLimit => {
				// We do not verify "tx as pool" weight so we are done here.
				return Ok(());
			}
		};

		if self.body_weight_as_block() > max_weight {
			return Err(Error::TooHeavy);
		}
		Ok(())
	}

	// Verify that inputs|outputs|kernels are sorted in lexicographical order
	// and that there are no duplicates (they are all unique within this transaction).
	fn verify_sorted(&self) -> Result<(), Error> {
		self.inputs.verify_sorted_and_unique()?;
		self.outputs.verify_sorted_and_unique()?;
		self.kernels.verify_sorted_and_unique()?;
		Ok(())
	}

	// Verify that no input is spending an output from the same block.
	// Assumes inputs and outputs are sorted
	fn verify_cut_through(&self) -> Result<(), Error> {
		let mut inputs = self.inputs.iter().map(|x| x.hash()).peekable();
		let mut outputs = self.outputs.iter().map(|x| x.id().hash()).peekable();
		while let (Some(ih), Some(oh)) = (inputs.peek(), outputs.peek()) {
			match ih.cmp(oh) {
				Ordering::Less => {
					inputs.next();
				}
				Ordering::Greater => {
					outputs.next();
				}
				Ordering::Equal => {
					return Err(Error::CutThrough);
				}
			}
		}
		Ok(())
	}

	/// Verify we have no invalid outputs or kernels in the transaction
	/// due to invalid features.
	/// Specifically, a transaction cannot contain a coinbase output or a coinbase kernel.
	pub fn verify_features(&self) -> Result<(), Error> {
		self.verify_output_features()?;
		self.verify_kernel_features()?;
		Ok(())
	}

	// Verify we have no outputs tagged as COINBASE.
	fn verify_output_features(&self) -> Result<(), Error> {
		if self.outputs.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	// Verify we have no kernels tagged as COINBASE.
	fn verify_kernel_features(&self) -> Result<(), Error> {
		if self.kernels.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidKernelFeatures);
		}
		Ok(())
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * InputUnlocker signature verification
	/// * kernel signature verification
	pub fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		self.verify_weight(weighting)?;
		self.verify_sorted()?;
		self.verify_cut_through()?;
		Ok(())
	}

	/// Validates all relevant parts of a transaction body. Checks the excess value against the signature,
	/// and the InputUnlocker signature if this transaction has SigLocked input.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		complete_inputs: Option<&HashMap<Commitment, OutputEx>>,
		height: u64,
	) -> Result<(), Error> {
		self.validate_read(weighting)?;

		// Collect all InputUnlocker(s)
		let inputs: Vec<InputEx> = self
			.inputs
			.iter()
			.filter(|i| i.is_unlocker())
			.cloned()
			.collect();

		// Find all the kernels that have not yet been verified.
		// Find all the InputEx that have not had their InputUnlocker verified.
		let (kernels, inputs) = {
			let mut verifier = verifier.write();
			(
				verifier.filter_kernel_sig_unverified(&self.kernels),
				verifier.filter_unlocker_unverified(&inputs),
			)
		};

		// Verify the unverified tx kernels.
		TxKernel::batch_sig_verify(&kernels)?;

		// Verify the unverified InputUnlocker.
		if !inputs.is_empty() {
			if complete_inputs.is_none() {
				// Caution:
				//  1. 'complete_inputs' parameter should be Some for validation on InputUnlocker signature.
				//  2. 'None' only for the case of avoid those duplicated validation on this.
				//return Err(Error::InputNotExist);
			} else {
				let complete_inputs = complete_inputs.unwrap();
				let len = inputs.len();
				let mut sigs: Vec<secp::Signature> = Vec::with_capacity(len);
				let mut pubkeys: Vec<secp::key::PublicKey> = Vec::with_capacity(len);
				let mut msgs: Vec<secp::Message> = Vec::with_capacity(len);

				for input_ex in &inputs {
					if input_ex.is_unlocker() {
						// Collect all related outputs to spent
						let commits = input_ex.commitments();
						let mut outputs_to_spent: Vec<OutputEx> = Vec::with_capacity(commits.len());
						for commit in &commits {
							let output_ex = complete_inputs
								.get(commit)
								.ok_or(Error::InputNotExist)?
								.clone();
							// Verify the Relative Lock Height
							if height
								< output_ex.output.get_rlh().unwrap() as u64 + output_ex.height
							{
								return Err(Error::InputUnlocker(
									"relative_lock_height limited".to_string(),
								));
							}
							outputs_to_spent.push(output_ex);
						}

						let (sig, msg, pubkey) = input_ex.verify(&outputs_to_spent)?;
						sigs.push(sig);
						pubkeys.push(pubkey);
						msgs.push(msg);
					}
				}

				let secp = static_secp_instance();
				let secp = secp.lock();

				if !secp::aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
					return Err(Error::UnlockerIncorrectSignature);
				}
			}
		}

		// Cache the successful verification results.
		// todo: failed verification result no need to cache?
		{
			let mut verifier = verifier.write();
			verifier.add_kernel_sig_verified(kernels);
			verifier.add_unlocker_verified(inputs);
		}
		Ok(())
	}
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBody,
}

impl DefaultHashable for Transaction {}

/// PartialEq
impl PartialEq for Transaction {
	fn eq(&self, tx: &Transaction) -> bool {
		self.body == tx.body
	}
}

impl Into<TransactionBody> for Transaction {
	fn into(self) -> TransactionBody {
		self.body
	}
}

/// Implementation of Writeable for a fully blinded transaction, defines how to
/// write the transaction as binary.
impl Writeable for Transaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.body.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction, defines how to read a full
/// transaction from a binary stream.
impl Readable for Transaction {
	fn read(reader: &mut dyn Reader) -> Result<Transaction, ser::Error> {
		let body = TransactionBody::read(reader)?;
		let tx = Transaction { body };

		// Now "lightweight" validation of the tx.
		// Treat any validation issues as data corruption.
		// An example of this would be reading a tx
		// that exceeded the allowed number of inputs.
		tx.validate_read().map_err(|_| ser::Error::CorruptedData)?;

		Ok(tx)
	}
}

impl Committed for Transaction {
	fn inputs_committed(&self) -> Vec<Commitment> {
		self.body.inputs_committed()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.body.outputs_committed()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.body.kernels_committed()
	}
}

impl Default for Transaction {
	fn default() -> Transaction {
		Transaction::empty()
	}
}

impl Transaction {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> Transaction {
		Transaction {
			body: Default::default(),
		}
	}

	/// Creates a new transaction initialized with
	/// the provided inputs, outputs, kernels
	pub fn new(inputs: Vec<InputEx>, outputs: Vec<Output>, kernels: Vec<TxKernel>) -> Transaction {
		// Initialize a new tx body and sort everything.
		let body =
			TransactionBody::init(inputs, outputs, kernels, false).expect("sorting, not verifying");

		Transaction { body }
	}

	/// Builds a new transaction with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(self, input: Input) -> Transaction {
		Transaction {
			body: self.body.with_input(input),
			..self
		}
	}

	/// Builds a new transaction with the provided InputEx added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input_ex(self, input_ex: InputEx) -> Transaction {
		Transaction {
			body: self.body.with_input_ex(input_ex),
			..self
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> Transaction {
		Transaction {
			body: self.body.with_output(output),
			..self
		}
	}

	/// Builds a new transaction with the provided outputs added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_outputs(self, outputs: Vec<Output>) -> Transaction {
		Transaction {
			body: self.body.with_outputs(outputs),
			..self
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> Transaction {
		Transaction {
			body: self.body.with_kernel(kernel),
			..self
		}
	}

	/// Get inputs
	pub fn inputs(&self) -> Vec<Input> {
		self.body.inputs()
	}

	/// Get inputs
	pub fn inputs_ex(&self) -> &Vec<InputEx> {
		&self.body.inputs
	}

	/// Get inputs mutable
	pub fn inputs_ex_mut(&mut self) -> &mut Vec<InputEx> {
		&mut self.body.inputs
	}

	/// Get outputs
	pub fn outputs(&self) -> &Vec<Output> {
		&self.body.outputs
	}

	/// Get output by commit
	pub fn find_output_by_commit(&self, commit: &Commitment) -> Option<&Output> {
		self.body.outputs.iter().find(|o| &o.commitment() == commit)
	}

	/// Get outputs mutable
	pub fn outputs_mut(&mut self) -> &mut Vec<Output> {
		&mut self.body.outputs
	}

	/// Get kernels
	pub fn kernels(&self) -> &Vec<TxKernel> {
		&self.body.kernels
	}

	/// Get kernels mut
	pub fn kernels_mut(&mut self) -> &mut Vec<TxKernel> {
		&mut self.body.kernels
	}

	/// Total fee for a transaction is the sum of fees of all kernels.
	pub fn fee(&self) -> u64 {
		self.body.fee()
	}

	/// Total overage across all kernels.
	pub fn overage(&self) -> i64 {
		self.body.overage()
	}

	/// Lock height of a transaction is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.body.lock_height()
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification (on the body)
	/// * kernel signature verification (on the body)
	/// * kernel sum verification
	pub fn validate_read(&self) -> Result<(), Error> {
		self.body.validate_read(Weighting::AsTransaction)?;
		self.body.verify_features()?;
		Ok(())
	}

	/// Validates all relevant parts of a fully built transaction.
	/// - Checks the excess value against the signature
	/// - Checks the unlocker signature and p2pkh match
	/// - Checks the public value balance.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		complete_inputs: Option<&HashMap<Commitment, OutputEx>>,
		height: u64,
	) -> Result<(), Error> {
		self.body
			.validate(weighting, verifier, complete_inputs, height)?;
		self.body.verify_features()?;

		// validate the public value balance.
		// Caution:
		//  1. 'complete_inputs' parameter should be Some for validation on sum balance.
		//  2. 'None' only for the case of avoid those duplicated validation on this.
		if let Some(complete_inputs) = complete_inputs {
			let mut sum: i64 = complete_inputs
				.values()
				.fold(0i64, |acc, x| acc.saturating_add(x.output.value as i64));
			sum = self
				.body
				.outputs
				.iter()
				.fold(sum, |acc, x| acc.saturating_sub(x.value as i64));
			if sum != self.overage() {
				return Err(Error::TransactionSumMismatch)?;
			}
		}

		self.verify_kernel_sums()?;
		Ok(())
	}

	/// Can be used to compare txs by their fee/weight ratio.
	/// Don't use these values for anything else though due to precision multiplier.
	pub fn fee_to_weight(&self) -> u64 {
		self.fee() * 1_000 / self.tx_weight() as u64
	}

	/// Calculate transaction weight
	pub fn tx_weight(&self) -> usize {
		self.body.body_weight()
	}

	/// Calculate transaction weight as a block
	pub fn tx_weight_as_block(&self) -> usize {
		self.body.body_weight_as_block()
	}

	/// Calculate transaction weight from transaction details
	pub fn weight(input_len: usize, output_len: usize, kernel_len: usize) -> usize {
		TransactionBody::weight(input_len, output_len, kernel_len)
	}
}

/// Matches any output with a potential spending input, eliminating them
/// from the Vec. Provides a simple way to cut-through a block or aggregated
/// transaction. The elimination is stable with respect to the order of inputs
/// and outputs.
/// Cut-Through in same block is forbidden for Non-Interactive Transaction, please
/// refer to docs/intro.md#coinjoin-forbidden-for-non-interactive-transaction.
pub fn cut_through(inputs_ex: &mut Vec<InputEx>, outputs: &mut Vec<Output>) -> Result<(), Error> {
	// assemble output commitments set, checking they're all unique
	outputs.sort_unstable();
	if outputs.windows(2).any(|pair| pair[0] == pair[1]) {
		return Err(Error::AggregationError);
	}

	//todo: SigLocked Output cut-through, InputsWithUnlocker cut-through
	let mut inputs: Vec<Input> = inputs_ex
		.iter()
		.filter(|i| !i.is_unlocker())
		.map(|i| i.get_single_input().unwrap())
		.collect();

	inputs.sort_unstable();
	let mut inputs_idx = 0;
	let mut outputs_idx = 0;
	let mut ncut = 0;
	while inputs_idx < inputs.len() && outputs_idx < outputs.len() {
		match inputs[inputs_idx]
			.hash()
			.cmp(&outputs[outputs_idx].id().hash())
		{
			Ordering::Less => {
				inputs[inputs_idx - ncut] = inputs[inputs_idx];
				inputs_idx += 1;
			}
			Ordering::Greater => {
				outputs[outputs_idx - ncut] = outputs[outputs_idx];
				outputs_idx += 1;
			}
			Ordering::Equal => {
				inputs_idx += 1;
				outputs_idx += 1;
				ncut += 1;
			}
		}
	}
	// Cut elements that have already been copied
	outputs.drain(outputs_idx - ncut..outputs_idx);
	inputs.drain(inputs_idx - ncut..inputs_idx);

	// Cut from the inputs_ex
	let inputs_with_locker: Vec<InputEx> =
		inputs_ex.drain(..).filter(|i| i.is_unlocker()).collect();
	inputs_ex.clear();
	let left: Vec<InputEx> = inputs.iter().map(|i| i.to_input_ex()).collect();

	inputs_ex.extend_from_slice(&left);
	inputs_ex.extend_from_slice(&inputs_with_locker);

	Ok(())
}

/// Aggregate a vec of txs into a multi-kernel tx with cut_through.
pub fn aggregate(mut txs: Vec<Transaction>) -> Result<Transaction, Error> {
	// convenience short-circuiting
	if txs.is_empty() {
		return Ok(Transaction::empty());
	} else if txs.len() == 1 {
		return Ok(txs.pop().unwrap());
	}
	let mut n_inputs = 0;
	let mut n_outputs = 0;
	let mut n_kernels = 0;
	for tx in txs.iter() {
		n_inputs += tx.body.inputs.len();
		n_outputs += tx.body.outputs.len();
		n_kernels += tx.body.kernels.len();
	}

	let mut inputs: Vec<InputEx> = Vec::with_capacity(n_inputs);
	let mut outputs: Vec<Output> = Vec::with_capacity(n_outputs);
	let mut kernels: Vec<TxKernel> = Vec::with_capacity(n_kernels);

	for mut tx in txs {
		inputs.append(&mut tx.body.inputs);
		outputs.append(&mut tx.body.outputs);
		kernels.append(&mut tx.body.kernels);
	}

	// Sort inputs and outputs during cut_through.
	cut_through(&mut inputs, &mut outputs)?;

	// Now sort kernels.
	kernels.sort_unstable();

	// build a new aggregate tx from the following -
	//   * cut-through inputs
	//   * cut-through outputs
	//   * full set of tx kernels
	let tx = Transaction::new(inputs, outputs, kernels);

	Ok(tx)
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple
/// transactions
pub fn deaggregate(mk_tx: Transaction, txs: Vec<Transaction>) -> Result<Transaction, Error> {
	let mut inputs: Vec<InputEx> = vec![];
	let mut outputs: Vec<Output> = vec![];
	let mut kernels: Vec<TxKernel> = vec![];

	let tx = aggregate(txs)?;

	for mk_input in mk_tx.body.inputs {
		if !tx.body.inputs.contains(&mk_input) && !inputs.contains(&mk_input) {
			inputs.push(mk_input);
		}
	}
	for mk_output in mk_tx.body.outputs {
		if !tx.body.outputs.contains(&mk_output) && !outputs.contains(&mk_output) {
			outputs.push(mk_output);
		}
	}
	for mk_kernel in mk_tx.body.kernels {
		if !tx.body.kernels.contains(&mk_kernel) && !kernels.contains(&mk_kernel) {
			kernels.push(mk_kernel);
		}
	}

	// Sorting them lexicographically
	inputs.sort_unstable();
	outputs.sort_unstable();
	kernels.sort_unstable();

	// Build a new tx from the above data.
	let tx = Transaction::new(inputs, outputs, kernels);
	Ok(tx)
}

/// A transaction input.
///
/// Primarily a reference to an output being spent by the transaction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Input {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	pub commit: Commitment,
}

impl DefaultHashable for Input {}
hashable_ord!(Input);

impl ::std::hash::Hash for Input {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for Input {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for Input {
	fn read(reader: &mut dyn Reader) -> Result<Input, ser::Error> {
		let features = OutputFeatures::read(reader)?;
		let commit = Commitment::read(reader)?;
		Ok(Input::new(features, commit))
	}
}

/// The input for a transaction, which spends a pre-existing unspent output.
/// The input commitment is a reproduction of the commitment of the output
/// being spent. Input must also provide the original output features and the
/// hash of the block the output originated from.
impl Input {
	/// Build a new input from the data required to identify and verify an
	/// output being spent.
	pub fn new(features: OutputFeatures, commit: Commitment) -> Input {
		Input { features, commit }
	}

	/// Identifier for the output
	pub fn id(&self) -> OutputIdentifier {
		OutputIdentifier {
			features: self.features,
			commit: self.commit,
		}
	}

	/// The input commitment which _partially_ identifies the output being
	/// spent. In the presence of a fork we need additional info to uniquely
	/// identify the output. Specifically the block hash (to correctly
	/// calculate lock_height for coinbase outputs).
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase input?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain input?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Is this a SigLocked input?
	pub fn is_siglocked(&self) -> bool {
		self.features.is_siglocked()
	}
	/// Create an InputEx from an Input
	pub fn to_input_ex(&self) -> InputEx {
		InputEx::SingleInput(self.clone())
	}
}

/// The unlocker in a transaction input when spending an output with a locker.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct InputUnlocker {
	/// Timestamp at which the transaction was built.
	pub timestamp: DateTime<Utc>,
	/// The signature for the output which has a locked public key / address.
	#[serde(with = "secp_ser::sig_serde")]
	pub sig: secp::Signature,
	/// The public key.
	#[serde(with = "secp_ser::pubkey_serde")]
	pub pub_key: secp::key::PublicKey,
}

impl DefaultHashable for InputUnlocker {}
hashable_ord!(InputUnlocker);

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for InputUnlocker {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_i64(self.timestamp.timestamp())?;
		self.sig.write(writer)?;
		self.pub_key.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for InputUnlocker {
	fn read(reader: &mut dyn Reader) -> Result<InputUnlocker, ser::Error> {
		let timestamp = reader.read_i64()?;
		if timestamp > MAX_DATE.and_hms(0, 0, 0).timestamp()
			|| timestamp < MIN_DATE.and_hms(0, 0, 0).timestamp()
		{
			return Err(ser::Error::CorruptedData);
		}

		let sig = secp::Signature::read(reader)?;
		let pub_key = secp::key::PublicKey::read(reader)?;
		Ok(InputUnlocker {
			timestamp: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc),
			sig,
			pub_key,
		})
	}
}

/// The input of a transaction.
///
/// Primarily a reference to a batch of outputs (with same 'p2pkh' locker) being spent by the transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum InputEx {
	/// Single Input w/o unlocker
	SingleInput(Input),
	/// Single or multiple Inputs with unlocker
	InputsWithUnlocker {
		/// Inputs. To spend those outputs with same 'p2pkh' locker.
		inputs: Vec<Input>,
		/// The unlocker for spending one or a batch of output/s with same 'p2pkh' locker.
		unlocker: InputUnlocker,
	},
}
impl DefaultHashable for InputEx {}
hashable_ord!(InputEx);

impl ::std::hash::Hash for InputEx {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Inputs, defines how to write
/// an InputEx as binary.
impl Writeable for InputEx {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			InputEx::SingleInput(i) => {
				writer.write_u8(0u8)?;
				i.write(writer)?;
			}
			InputEx::InputsWithUnlocker { inputs, unlocker } => {
				assert!(inputs.len() <= u32::MAX as usize);
				writer.write_u8(1u8)?;
				writer.write_u32(inputs.len() as u32)?;
				inputs.write(writer)?;
				unlocker.write(writer)?;
			}
		}
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for InputEx {
	fn read(reader: &mut dyn Reader) -> Result<InputEx, ser::Error> {
		let input_type = reader.read_u8()?;
		match input_type {
			0 => {
				let input = Input::read(reader)?;
				Ok(InputEx::SingleInput(input))
			}
			1 => {
				let input_len = reader.read_u32()?;
				let inputs = read_multi(reader, input_len as u64)?;
				let unlocker = InputUnlocker::read(reader)?;
				Ok(InputEx::InputsWithUnlocker { inputs, unlocker })
			}
			_ => Err(ser::Error::CorruptedData),
		}
	}
}

/// The input for a transaction, which spends a pre-existing unspent output.
/// The input commitment is a reproduction of the commitment of the output
/// being spent. Input must also provide the original output features.
impl InputEx {
	/// Whether it contains an InputUnlocker
	pub fn is_unlocker(&self) -> bool {
		match self {
			InputEx::SingleInput(_) => false,
			InputEx::InputsWithUnlocker { .. } => true,
		}
	}

	/// Get the Input if it's a SingleInput.
	pub fn get_single_input(&self) -> Option<Input> {
		match self {
			InputEx::SingleInput(input) => Some(input.clone()),
			InputEx::InputsWithUnlocker { .. } => None,
		}
	}

	/// Get the InputUnlocker.
	pub fn get_unlocker(&self) -> Result<InputUnlocker, Error> {
		match self {
			InputEx::SingleInput(_) => Err(Error::InputUnlocker("wrong Input type".to_string())),
			InputEx::InputsWithUnlocker {
				inputs: _,
				unlocker,
			} => Ok(unlocker.clone()),
		}
	}

	/// The input commitment/s.
	pub fn commitments(&self) -> Vec<Commitment> {
		match self {
			InputEx::SingleInput(i) => vec![i.commit.clone()],
			InputEx::InputsWithUnlocker {
				inputs,
				unlocker: _,
			} => inputs.iter().map(|input| input.commit.clone()).collect(),
		}
	}

	/// The inputs.
	pub fn inputs(&self) -> Vec<Input> {
		match self {
			InputEx::SingleInput(i) => vec![i.clone()],
			InputEx::InputsWithUnlocker {
				inputs,
				unlocker: _,
			} => inputs.clone(),
		}
	}

	/// The vector length
	pub fn len(&self) -> usize {
		match self {
			InputEx::SingleInput(_) => 1,
			InputEx::InputsWithUnlocker {
				inputs,
				unlocker: _,
			} => inputs.len(),
		}
	}

	/// Verify the transaction proof validity. Entails checking the signature verifies with
	/// the ([(features || commit || value), ...] || nonce) as message.
	///
	/// Note: for the efficient signature batch verification, leave signature verification to the outside.
	pub fn verify(
		&self,
		outputs_to_spent: &Vec<OutputEx>,
	) -> Result<(secp::Signature, secp::Message, secp::key::PublicKey), Error> {
		if !self.is_unlocker() {
			return Err(Error::InputUnlocker("wrong Input type".to_string()));
		}

		if outputs_to_spent.is_empty() {
			return Err(Error::InputNotExist);
		}

		let unlocker = self.get_unlocker().unwrap();

		// All Inputs exist in 'outputs_to_spent'
		let commits_in = self.commitments();
		let commits_out: Vec<Commitment> = outputs_to_spent
			.iter()
			.map(|o| o.output.commit.clone())
			.collect();
		for commit in &commits_in {
			if !commits_out.contains(commit) {
				return Err(Error::InputNotExist);
			}
		}

		let p2pkh = unlocker.pub_key.serialize_vec(true).hash();
		let mut msg_to_sign: Vec<u8> = Vec::with_capacity(outputs_to_spent.len() * SINGLE_MSG_SIZE);

		// Assemble the signature msg from the outputs to spent, and verify the public key hash
		for output_ex in outputs_to_spent {
			if output_ex.output.pkh_locked() != Ok(p2pkh) {
				return Err(Error::IncorrectPubkey);
			}
			msg_to_sign.extend_from_slice(&output_ex.output.msg_to_sign()?);
		}

		// Hashing to get the final msg for signature
		let hash = (msg_to_sign, unlocker.timestamp.timestamp()).hash();
		let msg = secp::Message::from_slice(&hash.as_bytes())?;

		Ok((unlocker.sig, msg, unlocker.pub_key))
	}
}

// Enum of various supported output "features".
enum_from_primitive! {
	/// Enum of various flavors of output, in a single byte flag.
	#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
	#[repr(u8)]
	pub enum OutputFeatures {
		/// Plain output of Interactive Transaction.
		Plain = 0,
		/// A coinbase output.
		Coinbase = 1,
		/// Plain output of Non-Interactive Transaction.
		SigLocked = 2,
	}
}

impl Writeable for OutputFeatures {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(*self as u8)?;
		Ok(())
	}
}

impl Readable for OutputFeatures {
	fn read(reader: &mut dyn Reader) -> Result<OutputFeatures, ser::Error> {
		let features =
			OutputFeatures::from_u8(reader.read_u8()?).ok_or(ser::Error::CorruptedData)?;
		Ok(features)
	}
}

impl OutputFeatures {
	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		*self == OutputFeatures::Coinbase
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		*self == OutputFeatures::Plain
	}

	/// Is this a SigLocked output?
	pub fn is_siglocked(&self) -> bool {
		*self == OutputFeatures::SigLocked
	}
}

/// Enum of various flavors of output.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum OutputFeaturesEx {
	/// Plain output of Interactive Transaction.
	Plain {
		/// A secured path message which hide the key derivation path and the random w of commitment.
		#[serde(
			serialize_with = "secp_ser::as_hex",
			deserialize_with = "secp_ser::securedpath_from_hex"
		)]
		spath: SecuredPath,
	},
	/// Coinbase output.
	Coinbase {
		/// A secured path message, same as Plain.
		#[serde(
			serialize_with = "secp_ser::as_hex",
			deserialize_with = "secp_ser::securedpath_from_hex"
		)]
		spath: SecuredPath,
	},
	/// Plain output of Non-Interactive Transaction.
	SigLocked {
		/// A locker to make it only spendable for who can unlock it with a signature.
		locker: OutputLocker,
	},
}

impl OutputFeaturesEx {
	/// Underlying (u8) value representing this output variant.
	/// This is the first byte when we serialize/deserialize the output features.
	pub fn as_u8(&self) -> u8 {
		match self {
			OutputFeaturesEx::Plain { .. } => OutputFeatures::Plain as u8,
			OutputFeaturesEx::Coinbase { .. } => OutputFeatures::Coinbase as u8,
			OutputFeaturesEx::SigLocked { .. } => OutputFeatures::SigLocked as u8,
		}
	}

	/// Underlying enum flag representing this output variant.
	pub fn as_flag(&self) -> OutputFeatures {
		match self {
			OutputFeaturesEx::Plain { .. } => OutputFeatures::Plain,
			OutputFeaturesEx::Coinbase { .. } => OutputFeatures::Coinbase,
			OutputFeaturesEx::SigLocked { .. } => OutputFeatures::SigLocked,
		}
	}

	/// Conversion for backward compatibility.
	pub fn as_string(&self) -> String {
		match self {
			OutputFeaturesEx::Plain { .. } => String::from("Plain"),
			OutputFeaturesEx::Coinbase { .. } => String::from("Coinbase"),
			OutputFeaturesEx::SigLocked { .. } => String::from("SigLocked"),
		}
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.as_flag() == OutputFeatures::Coinbase
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		let features = self.as_flag();
		features == OutputFeatures::Plain || features == OutputFeatures::SigLocked
	}

	/// Is this a SigLocked output?
	pub fn is_siglocked(&self) -> bool {
		self.as_flag() == OutputFeatures::SigLocked
	}

	/// Get the SecuredPath if this is not a SigLocked output
	pub fn get_spath(&self) -> Result<&SecuredPath, Error> {
		match self {
			OutputFeaturesEx::Plain { spath } => Ok(spath),
			OutputFeaturesEx::Coinbase { spath } => Ok(spath),
			OutputFeaturesEx::SigLocked { .. } => {
				Err(Error::SecuredPath("type not match".to_owned()))
			}
		}
	}

	/// Get the SecuredPath if this is not a SigLocked output
	pub fn get_locker(&self) -> Result<&OutputLocker, Error> {
		match self {
			OutputFeaturesEx::Plain { .. } | OutputFeaturesEx::Coinbase { .. } => {
				Err(Error::SecuredPath("type not match".to_owned()))
			}
			OutputFeaturesEx::SigLocked { locker } => Ok(locker),
		}
	}
}

impl Writeable for OutputFeaturesEx {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.as_u8())?;
		match self {
			OutputFeaturesEx::Plain { spath } => {
				spath.write(writer)?;
			}
			OutputFeaturesEx::Coinbase { spath } => {
				spath.write(writer)?;
			}
			OutputFeaturesEx::SigLocked { locker } => {
				locker.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for OutputFeaturesEx {
	fn read(reader: &mut dyn Reader) -> Result<OutputFeaturesEx, ser::Error> {
		let features =
			OutputFeatures::from_u8(reader.read_u8()?).ok_or(ser::Error::CorruptedData)?;
		let features = match features {
			OutputFeatures::Plain => OutputFeaturesEx::Plain {
				spath: SecuredPath::read(reader)?,
			},
			OutputFeatures::Coinbase => OutputFeaturesEx::Coinbase {
				spath: SecuredPath::read(reader)?,
			},
			OutputFeatures::SigLocked => OutputFeaturesEx::SigLocked {
				locker: OutputLocker::read(reader)?,
			},
		};
		Ok(features)
	}
}

/// Output with block height and mmr index
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutputEx {
	/// The output
	pub output: Output,
	/// Height of the block which contains the output
	pub height: u64,
	/// MMR Index of output
	pub mmr_index: u64,
}

/// Output for a transaction, defining the new ownership of coins that are being
/// transferred. The commitment is a blinded value for the output and the ownership
/// of the private key.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Output {
	/// Options for an output's structure or use
	pub features: OutputFeaturesEx,
	/// The homomorphic commitment representing the output amount
	pub commit: Commitment,
	/// The explicit amount
	pub value: u64,
}

impl DefaultHashable for Output {}

impl PMMRIndexHashable for Output {
	fn hash_with_index(&self, index: u64) -> Hash {
		match self.features.as_flag() {
			OutputFeatures::Plain | OutputFeatures::Coinbase => {
				OutputI::from_output(&self).unwrap().hash_with_index(index)
			}
			OutputFeatures::SigLocked => {
				OutputII::from_output(&self).unwrap().hash_with_index(index)
			}
		}
	}
}

impl Ord for Output {
	fn cmp(&self, other: &Output) -> Ordering {
		self.id().cmp(&other.id())
	}
}
impl PartialOrd for Output {
	fn partial_cmp(&self, other: &Output) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

/// Use id() instead of the hash() for Eq, for the convenience of Input/Output compare.
/// todo: then, how to give the exact content comparing?
impl PartialEq for Output {
	fn eq(&self, other: &Output) -> bool {
		self.id() == other.id()
	}
}
impl Eq for Output {}

impl ::std::hash::Hash for Output {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
/// Note: To make it simple among all 3 types: Output, OutputI, and OutputII, we define same Hash
/// for all of them:
/// 1. Only the OutputIdentifier is used for Hash.
/// 2. All 3 types (Output, OutputI, OutputII) have same Hash result.
impl Writeable for Output {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if writer.serialization_mode() == ser::SerializationMode::Hash {
			// The hash of an output ONLY include its id(), i.e. the features flag and the commit.
			writer.write_u8(self.features.as_u8())?;
			self.commit.write(writer)?;
		} else {
			self.features.write(writer)?;
			self.commit.write(writer)?;
			writer.write_u64(self.value)?;
		}
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for Output {
	fn read(reader: &mut dyn Reader) -> Result<Output, ser::Error> {
		let features = OutputFeaturesEx::read(reader)?;
		let commit = Commitment::read(reader)?;
		let value = reader.read_u64()?;
		Ok(Output {
			features,
			commit,
			value,
		})
	}
}

impl Output {
	/// Identifier for the output
	pub fn id(&self) -> OutputIdentifier {
		OutputIdentifier {
			features: self.features.as_flag(),
			commit: self.commit,
		}
	}

	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// PublicKeyHash which this output has been locked on
	pub fn pkh_locked(&self) -> Result<Hash, Error> {
		match self.features {
			OutputFeaturesEx::Plain { .. } | OutputFeaturesEx::Coinbase { .. } => {
				Err(Error::OutputLocker("output w/o locker".to_owned()))
			}
			OutputFeaturesEx::SigLocked { locker } => Ok(locker.p2pkh),
		}
	}

	/// Get the relative lock height if it's SigLocked Output
	pub fn get_rlh(&self) -> Result<u32, Error> {
		match self.features {
			OutputFeaturesEx::Plain { .. } | OutputFeaturesEx::Coinbase { .. } => {
				Err(Error::OutputLocker("output w/o locker".to_owned()))
			}
			OutputFeaturesEx::SigLocked { locker } => Ok(locker.relative_lock_height),
		}
	}

	/// PathMessage for the output
	pub fn path_message(&self, rewind_hash: &Hash) -> Result<PathMessage, Error> {
		let rewind_nonce =
			Hash::from_vec(blake2b(32, &self.commit.0, rewind_hash.as_bytes()).as_bytes());
		match self.features {
			OutputFeaturesEx::Plain { spath } => spath
				.get_path(&rewind_nonce)
				.map_err(|e| Error::SecuredPath(e.to_string())),
			OutputFeaturesEx::Coinbase { spath } => spath
				.get_path(&rewind_nonce)
				.map_err(|e| Error::SecuredPath(e.to_string())),
			OutputFeaturesEx::SigLocked { .. } => {
				Err(Error::SecuredPath("output w/o SecuredPath".to_owned()))
			}
		}
	}

	/// The msg signed as part of the Input with a signature.
	/// 	msg = hash(features || commit || value || timestamp) for single input
	/// 	msg = hash((features || commit || value) || (...) || nonce) for multiple inputs
	/// Leave to caller to execute the final hash.
	pub fn msg_to_sign(&self) -> Result<Vec<u8>, Error> {
		match self.features {
			OutputFeaturesEx::SigLocked { .. } => {
				let mut msg: Vec<u8> = Vec::with_capacity(SINGLE_MSG_SIZE);
				msg.push(self.features.as_u8());
				msg.extend_from_slice(self.commit.clone().as_ref());
				msg.extend_from_slice(&self.value.to_be_bytes());
				Ok(msg)
			}
			_ => Err(Error::InvalidInputSigMsg),
		}
	}

	/// Return the binary of output, unhashed
	pub fn to_vec(&self) -> Vec<u8> {
		let mut bin_buf = vec![];
		{
			let mut writer = ser::BinWriter::default(&mut bin_buf);
			self.features.write(&mut writer).unwrap();
			self.commit.write(&mut writer).unwrap();
			writer.write_u64(self.value).unwrap();
		}
		bin_buf
	}

	/// Full hash with all contents.
	/// Note: the self.hash() only hash on id().
	pub fn full_hash(&self) -> Hash {
		self.to_vec().hash()
	}
}

/// OutputI.
/// To make an easy PMMRable type, we need a FixedLength element.
/// But SigLocked Output has different size from Plain and Coinbase output, so we wrap them into
/// two new wrapper types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputI {
	/// Output value
	pub value: u64,
	/// Output features and commit.
	pub id: OutputIdentifier,
	/// A secured path message which hide the key derivation path and the random w of commitment.
	pub spath: SecuredPath,
}

impl DefaultHashable for OutputI {}

impl Ord for OutputI {
	fn cmp(&self, other: &OutputI) -> Ordering {
		self.id.cmp(&other.id)
	}
}
impl PartialOrd for OutputI {
	fn partial_cmp(&self, other: &OutputI) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

/// Use id instead of the hash() for Eq, for the convenience of Input/Output compare.
/// For the exact content comparing, please use hash() instead.
impl PartialEq for OutputI {
	fn eq(&self, other: &OutputI) -> bool {
		self.id == other.id
	}
}
impl Eq for OutputI {}

impl ::std::hash::Hash for OutputI {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
impl Writeable for OutputI {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if writer.serialization_mode() == ser::SerializationMode::Hash {
			// The hash of an output ONLY include its id, i.e. the features flag and the commit.
			self.id.write(writer)?;
		} else {
			writer.write_u64(self.value)?;
			self.id.write(writer)?;
			self.spath.write(writer)?;
		}
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for OutputI {
	fn read(reader: &mut dyn Reader) -> Result<OutputI, ser::Error> {
		let value = reader.read_u64()?;
		let id = OutputIdentifier::read(reader)?;
		let spath = SecuredPath::read(reader)?;
		Ok(OutputI { value, id, spath })
	}
}

impl FixedLength for OutputI {
	const LEN: usize = 8 + (1 + secp::constants::PEDERSEN_COMMITMENT_SIZE) + SECURED_PATH_SIZE;
}

impl PMMRable for OutputI {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

impl PMMRIndexHashable for OutputI {
	fn hash_with_index(&self, index: u64) -> Hash {
		(index, self.to_vec()).hash()
	}
}

impl OutputI {
	/// Build an OutputI from an Output.
	pub fn from_output(output: &Output) -> Result<Self, Error> {
		Ok(OutputI {
			value: output.value,
			id: output.id(),
			spath: output.features.get_spath()?.clone(),
		})
	}

	/// Converts OutputI to an Output
	pub fn into_output(self) -> Output {
		let features = match self.id.features {
			OutputFeatures::Plain => OutputFeaturesEx::Plain { spath: self.spath },
			OutputFeatures::Coinbase => OutputFeaturesEx::Coinbase { spath: self.spath },
			OutputFeatures::SigLocked => panic!("impossible match"),
		};
		Output {
			features,
			commit: self.id.commit,
			value: self.value,
		}
	}

	/// Return the binary of OutputI, unhashed
	pub fn to_vec(&self) -> Vec<u8> {
		let mut bin_buf = vec![];
		{
			let mut writer = ser::BinWriter::default(&mut bin_buf);
			writer.write_u64(self.value).unwrap();
			self.id.write(&mut writer).unwrap();
			self.spath.write(&mut writer).unwrap();
		}
		bin_buf
	}

	/// Full hash with all contents.
	/// Note: the self.hash() only hash on id().
	pub fn full_hash(&self) -> Hash {
		self.to_vec().hash()
	}
}

/// OutputII
/// To make an easy PMMRable type, we need a FixedLength element.
/// But SigLocked Output has different size from Plain and Coinbase output, so we wrap them into
/// two new wrapper types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputII {
	/// Output value
	pub value: u64,
	/// Output features and commit.
	pub id: OutputIdentifier,
	/// A locker to make it only spendable for who can unlock it with a signature.
	pub locker: OutputLocker,
}

impl DefaultHashable for OutputII {}

impl Ord for OutputII {
	fn cmp(&self, other: &OutputII) -> Ordering {
		self.id.cmp(&other.id)
	}
}
impl PartialOrd for OutputII {
	fn partial_cmp(&self, other: &OutputII) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

/// Use id instead of the hash() for Eq, for the convenience of Input/Output compare.
/// For the exact content comparing, please use hash() instead.
impl PartialEq for OutputII {
	fn eq(&self, other: &OutputII) -> bool {
		self.id == other.id
	}
}
impl Eq for OutputII {}

impl ::std::hash::Hash for OutputII {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
impl Writeable for OutputII {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if writer.serialization_mode() == ser::SerializationMode::Hash {
			// The hash of an output ONLY include its id, i.e. the features flag and the commit.
			self.id.write(writer)?;
		} else {
			writer.write_u64(self.value)?;
			self.id.write(writer)?;
			self.locker.write(writer)?;
		}
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for OutputII {
	fn read(reader: &mut dyn Reader) -> Result<OutputII, ser::Error> {
		let value = reader.read_u64()?;
		let id = OutputIdentifier::read(reader)?;
		let locker = OutputLocker::read(reader)?;
		Ok(OutputII { value, id, locker })
	}
}

impl FixedLength for OutputII {
	const LEN: usize = 8 + (1 + secp::constants::PEDERSEN_COMMITMENT_SIZE) + OUTPUT_LOCKER_SIZE;
}

impl PMMRable for OutputII {
	type E = Self;

	fn as_elmt(&self) -> Self::E {
		self.clone()
	}
}

impl PMMRIndexHashable for OutputII {
	fn hash_with_index(&self, index: u64) -> Hash {
		(index, self.to_vec()).hash()
	}
}

impl OutputII {
	/// Build an OutputII from an Output.
	pub fn from_output(output: &Output) -> Result<Self, Error> {
		Ok(OutputII {
			value: output.value,
			id: output.id(),
			locker: output.features.get_locker()?.clone(),
		})
	}

	/// Converts OutputII to an Output
	pub fn into_output(self) -> Output {
		let features = match self.id.features {
			OutputFeatures::Plain | OutputFeatures::Coinbase => panic!("impossible match"),
			OutputFeatures::SigLocked => OutputFeaturesEx::SigLocked {
				locker: self.locker,
			},
		};
		Output {
			features,
			commit: self.id.commit,
			value: self.value,
		}
	}

	/// Return the binary of OutputII, unhashed
	pub fn to_vec(&self) -> Vec<u8> {
		let mut bin_buf = vec![];
		{
			let mut writer = ser::BinWriter::default(&mut bin_buf);
			writer.write_u64(self.value).unwrap();
			self.id.write(&mut writer).unwrap();
			self.locker.write(&mut writer).unwrap();
		}
		bin_buf
	}

	/// Full hash with all contents.
	/// Note: the self.hash() only hash on id().
	pub fn full_hash(&self) -> Hash {
		self.to_vec().hash()
	}
}

/// An output_identifier can be build from either an input _or_ an output and
/// contains everything we need to uniquely identify an output being spent.
/// Needed because it is not sufficient to pass a commitment around.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputIdentifier {
	/// Output features (coinbase vs. regular transaction output)
	/// We need to include this when hashing to ensure coinbase maturity can be
	/// enforced.
	pub features: OutputFeatures,
	/// Output commitment
	pub commit: Commitment,
}

impl DefaultHashable for OutputIdentifier {}
hashable_ord!(OutputIdentifier);

impl ::std::hash::Hash for OutputIdentifier {
	fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
		let mut vec = Vec::new();
		ser::serialize_default(&mut vec, &self).expect("serialization failed");
		::std::hash::Hash::hash(&vec, state);
	}
}

impl OutputIdentifier {
	/// Build a new output_identifier.
	pub fn new(features: OutputFeatures, commit: &Commitment) -> OutputIdentifier {
		OutputIdentifier {
			features,
			commit: *commit,
		}
	}

	/// Our commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Build an output_identifier from an existing output.
	pub fn from_output(output: &Output) -> OutputIdentifier {
		OutputIdentifier {
			features: output.features.as_flag(),
			commit: output.commit,
		}
	}

	/// convert an output_identifier to hex string format.
	pub fn to_hex(&self) -> String {
		format!(
			"{:b}{}",
			self.features as u8,
			util::to_hex(self.commit.0.to_vec()),
		)
	}

	/// convert an output_identifier to vector.
	pub fn to_vec(&self) -> Vec<u8> {
		let mut ret: Vec<u8> = Vec::with_capacity(1 + secp::constants::PEDERSEN_COMMITMENT_SIZE);
		ret.push(self.features as u8);
		ret.extend_from_slice(&self.commit.0);
		ret
	}
}

impl Writeable for OutputIdentifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.commit.write(writer)?;
		Ok(())
	}
}

impl Readable for OutputIdentifier {
	fn read(reader: &mut dyn Reader) -> Result<OutputIdentifier, ser::Error> {
		Ok(OutputIdentifier {
			features: OutputFeatures::read(reader)?,
			commit: Commitment::read(reader)?,
		})
	}
}

impl From<Output> for OutputIdentifier {
	fn from(out: Output) -> Self {
		OutputIdentifier::from_output(&out)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hash;
	use crate::core::id::{ShortId, ShortIdentifiable};
	use crate::keychain::{ExtKeychain, Keychain};
	use crate::util::secp;
	use rand::{thread_rng, Rng};

	#[test]
	fn test_kernel_ser_deser() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let w: i64 = thread_rng().gen();
		let commit = keychain.commit(w, &key_id).unwrap();

		// just some bytes for testing ser/deser
		let sig = secp::Signature::from_raw_data(&[0; 64]).unwrap();

		let kernel = TxKernel {
			features: KernelFeatures::Plain { fee: 10 },
			excess: commit,
			excess_sig: sig.clone(),
		};

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(kernel2.features, KernelFeatures::Plain { fee: 10 });
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());

		// now check a kernel with lock_height serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::HeightLocked {
				fee: 10,
				lock_height: 100,
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(
			kernel2.features,
			KernelFeatures::HeightLocked {
				fee: 10,
				lock_height: 100
			}
		);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn commit_consistency() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let w: i64 = thread_rng().gen();
		let commit = keychain.commit(w, &key_id).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);

		let commit_2 = keychain.commit(w, &key_id).unwrap();

		assert!(commit == commit_2);
	}

	#[test]
	fn input_short_id() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let w = 9999i64;
		let commit = keychain.commit(w, &key_id).unwrap();

		let input = Input {
			features: OutputFeatures::Plain,
			commit,
		};

		let block_hash =
			Hash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();

		let nonce = 0;

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("cf2483f90e64").unwrap());

		// now generate the short_id for a *very* similar output (single feature flag
		// different) and check it generates a different short_id
		let input = Input {
			features: OutputFeatures::Coinbase,
			commit,
		};

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("933d5a52f535").unwrap());
	}

	#[test]
	fn kernel_features_serialization() {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(0u8, 10u64, 0u64)).expect("serialized failed");
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(features, KernelFeatures::Plain { fee: 10 });

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(1u8, 0u64, 0u64)).expect("serialized failed");
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(features, KernelFeatures::Coinbase);

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(2u8, 10u64, 100u64)).expect("serialized failed");
		let features: KernelFeatures = ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(
			features,
			KernelFeatures::HeightLocked {
				fee: 10,
				lock_height: 100
			}
		);

		let mut vec = vec![];
		ser::serialize_default(&mut vec, &(3u8, 0u64, 0u64)).expect("serialized failed");
		let res: Result<KernelFeatures, _> = ser::deserialize_default(&mut &vec[..]);
		assert_eq!(res.err(), Some(ser::Error::CorruptedData));
	}
}
