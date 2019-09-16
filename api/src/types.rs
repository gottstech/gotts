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

use std::sync::Arc;

use crate::chain;
use crate::core::core::hash::Hashed;
use crate::core::core::merkle_proof::MerkleProof;
use crate::core::core::{KernelFeatures, TxKernel};
use crate::core::{core, ser};
use crate::p2p;
use crate::util;
use crate::util::secp::pedersen;
use serde;
use std::fmt;

/// API Version Information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Version {
	/// Current node API Version (api crate version)
	pub node_version: String,
	/// Block header version
	pub block_header_version: u16,
}

/// The state of the current fork tip
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tip {
	/// Height of the tip (max height of the fork)
	pub height: u64,
	// Last block pushed to the fork
	pub last_block_pushed: String,
	// Block previous to last
	pub prev_block_to_last: String,
	// Total difficulty accumulated on that fork
	pub total_difficulty: u64,
}

impl Tip {
	pub fn from_tip(tip: chain::Tip) -> Tip {
		Tip {
			height: tip.height,
			last_block_pushed: util::to_hex(tip.last_block_h.to_vec()),
			prev_block_to_last: util::to_hex(tip.prev_block_h.to_vec()),
			total_difficulty: tip.total_difficulty.to_num(),
		}
	}
}

/// Status page containing different server information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Status {
	// The protocol version
	pub protocol_version: u32,
	// The user user agent
	pub user_agent: String,
	// The current number of connections
	pub connections: u32,
	// The state of the current fork Tip
	pub tip: Tip,
}

impl Status {
	pub fn from_tip_and_peers(current_tip: chain::Tip, connections: u32) -> Status {
		Status {
			protocol_version: ser::ProtocolVersion::local().into(),
			user_agent: p2p::msg::USER_AGENT.to_string(),
			connections: connections,
			tip: Tip::from_tip(current_tip),
		}
	}
}

/// TxHashSet
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxHashSet {
	/// Output Root Hash
	pub output_root_hash: String,
	// Rangeproof root hash
	pub range_proof_root_hash: String,
	// Kernel set root hash
	pub kernel_root_hash: String,
}

impl TxHashSet {
	pub fn from_head(head: Arc<chain::Chain>) -> TxHashSet {
		let roots = head.get_txhashset_roots();
		TxHashSet {
			output_root_hash: roots.output_i_root.to_hex(),
			range_proof_root_hash: roots.rproof_root.to_hex(),
			kernel_root_hash: roots.kernel_root.to_hex(),
		}
	}
}

/// Wrapper around a list of txhashset nodes, so it can be
/// presented properly via json
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxHashSetNode {
	// The hash
	pub hash: String,
}

impl TxHashSetNode {
	pub fn get_last_n_output(chain: Arc<chain::Chain>, distance: u64) -> Vec<TxHashSetNode> {
		let mut return_vec = Vec::new();
		let last_n = chain.get_last_n_output_i(distance);
		for x in last_n {
			return_vec.push(TxHashSetNode {
				hash: util::to_hex(x.0.to_vec()),
			});
		}
		return_vec
	}

	pub fn get_last_n_rangeproof(head: Arc<chain::Chain>, distance: u64) -> Vec<TxHashSetNode> {
		let mut return_vec = Vec::new();
		let last_n = head.get_last_n_rangeproof(distance);
		for elem in last_n {
			return_vec.push(TxHashSetNode {
				hash: util::to_hex(elem.0.to_vec()),
			});
		}
		return_vec
	}

	pub fn get_last_n_kernel(head: Arc<chain::Chain>, distance: u64) -> Vec<TxHashSetNode> {
		let mut return_vec = Vec::new();
		let last_n = head.get_last_n_kernel(distance);
		for elem in last_n {
			return_vec.push(TxHashSetNode {
				hash: util::to_hex(elem.0.to_vec()),
			});
		}
		return_vec
	}
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum OutputType {
	Coinbase,
	Transaction,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Output {
	/// The output commitment representing the amount
	pub commit: PrintableCommitment,
	/// Height of the block which contains the output
	pub height: u64,
	/// MMR Index of output
	pub mmr_index: u64,
}

impl Output {
	pub fn new(commit: &pedersen::Commitment, height: u64, mmr_index: u64) -> Output {
		Output {
			commit: PrintableCommitment {
				commit: commit.clone(),
			},
			height: height,
			mmr_index: mmr_index,
		}
	}
}

#[derive(Debug, Clone)]
pub struct PrintableCommitment {
	pub commit: pedersen::Commitment,
}

impl PrintableCommitment {
	pub fn commit(&self) -> pedersen::Commitment {
		self.commit.clone()
	}

	pub fn to_vec(&self) -> Vec<u8> {
		self.commit.0.to_vec()
	}
}

impl serde::ser::Serialize for PrintableCommitment {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::ser::Serializer,
	{
		serializer.serialize_str(&util::to_hex(self.to_vec()))
	}
}

impl<'de> serde::de::Deserialize<'de> for PrintableCommitment {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		deserializer.deserialize_str(PrintableCommitmentVisitor)
	}
}

struct PrintableCommitmentVisitor;

impl<'de> serde::de::Visitor<'de> for PrintableCommitmentVisitor {
	type Value = PrintableCommitment;

	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("a Pedersen commitment")
	}

	fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
	where
		E: serde::de::Error,
	{
		Ok(PrintableCommitment {
			commit: pedersen::Commitment::from_vec(
				util::from_hex(String::from(v)).map_err(serde::de::Error::custom)?,
			),
		})
	}
}

// As above, except formatted a bit better for human viewing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputPrintable {
	/// The type of output Coinbase|Transaction
	pub output_type: OutputType,
	/// The homomorphic commitment representing the output's amount (as hex string)
	pub commit: pedersen::Commitment,
	/// Whether the output has been spent
	pub spent: bool,
	/// Block height at which the output is found
	pub block_height: Option<u64>,
	/// Merkle Proof
	pub merkle_proof: Option<MerkleProof>,
	/// MMR Position
	pub mmr_index: u64,
}

impl OutputPrintable {
	pub fn from_output(
		output: &core::Output,
		chain: Arc<chain::Chain>,
		block_header: Option<&core::BlockHeader>,
		include_merkle_proof: bool,
	) -> Result<OutputPrintable, chain::Error> {
		let output_type = if output.is_coinbase() {
			OutputType::Coinbase
		} else {
			OutputType::Transaction
		};

		let out_id = core::OutputIdentifier::from_output(&output);
		let res = chain.is_unspent(&out_id);
		let (spent, block_height) = if let Ok(output_pos) = res {
			(false, Some(output_pos.height))
		} else {
			(true, None)
		};

		// Get the Merkle proof for all unspent coinbase outputs (to verify maturity on
		// spend). We obtain the Merkle proof by rewinding the PMMR.
		// We require the rewind() to be stable even after the PMMR is pruned and
		// compacted so we can still recreate the necessary proof.
		let mut merkle_proof = None;
		if include_merkle_proof && output.is_coinbase() && !spent {
			if let Some(block_header) = block_header {
				merkle_proof = chain.get_merkle_proof(&out_id, &block_header).ok();
			}
		};

		let output_pos_height = chain
			.get_output_pos_height(&output.commit)
			.unwrap_or((0, 0));

		Ok(OutputPrintable {
			output_type,
			commit: output.commit,
			spent,
			block_height,
			merkle_proof,
			mmr_index: output_pos_height.0,
		})
	}

	pub fn commit(&self) -> Result<pedersen::Commitment, ser::Error> {
		Ok(self.commit.clone())
	}
}

// Printable representation of a block
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxKernelPrintable {
	pub features: String,
	pub fee: u64,
	pub lock_height: u64,
	pub excess: String,
	pub excess_sig: String,
}

impl TxKernelPrintable {
	pub fn from_txkernel(k: &core::TxKernel) -> TxKernelPrintable {
		let features = k.features.as_string();
		let (fee, lock_height) = match k.features {
			KernelFeatures::Plain { fee } => (fee, 0),
			KernelFeatures::Coinbase => (0, 0),
			KernelFeatures::HeightLocked { fee, lock_height } => (fee, lock_height),
		};
		TxKernelPrintable {
			features,
			fee,
			lock_height,
			excess: util::to_hex(k.excess.0.to_vec()),
			excess_sig: util::to_hex(k.excess_sig.to_raw_data().to_vec()),
		}
	}
}

// Just the information required for wallet reconstruction
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeaderInfo {
	// Hash
	pub hash: String,
	/// Height of this block since the genesis block (height 0)
	pub height: u64,
	/// Hash of the block previous to this in the chain.
	pub previous: String,
}

impl BlockHeaderInfo {
	pub fn from_header(header: &core::BlockHeader) -> BlockHeaderInfo {
		BlockHeaderInfo {
			hash: util::to_hex(header.hash().to_vec()),
			height: header.height,
			previous: util::to_hex(header.prev_hash.to_vec()),
		}
	}
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct BlockHeaderPrintable {
	// Hash
	pub hash: String,
	/// Version of the block
	pub version: u16,
	/// Height of this block since the genesis block (height 0)
	pub height: u64,
	/// Hash of the block previous to this in the chain.
	pub previous: String,
	/// Root hash of the header MMR at the previous header.
	pub prev_root: String,
	/// rfc3339 timestamp at which the block was built.
	pub timestamp: String,
	/// Merklish root of all the commitments in the TxHashSet
	pub output_root: String,
	/// Merklish root of all range proofs in the TxHashSet
	pub range_proof_root: String,
	/// Merklish root of all transaction kernels in the TxHashSet
	pub kernel_root: String,
	/// Nonce increment used to mine this block.
	pub nonce: u64,
	/// Size of the cuckoo graph
	pub edge_bits: u8,
	/// Nonces of the cuckoo solution
	pub cuckoo_solution: Vec<u64>,
	/// Total accumulated difficulty since genesis block
	pub total_difficulty: u64,
	/// Variable difficulty scaling factor for secondary proof of work
	pub secondary_scaling: u32,
	/// Total kernel offset since genesis block
	pub total_kernel_offset: String,
}

impl BlockHeaderPrintable {
	pub fn from_header(header: &core::BlockHeader) -> BlockHeaderPrintable {
		BlockHeaderPrintable {
			hash: util::to_hex(header.hash().to_vec()),
			version: header.version.into(),
			height: header.height,
			previous: util::to_hex(header.prev_hash.to_vec()),
			prev_root: util::to_hex(header.prev_root.to_vec()),
			timestamp: header.timestamp.to_rfc3339(),
			output_root: util::to_hex(header.output_root.to_vec()),
			range_proof_root: util::to_hex(header.range_proof_root.to_vec()),
			kernel_root: util::to_hex(header.kernel_root.to_vec()),
			nonce: header.pow.nonce,
			edge_bits: header.pow.edge_bits(),
			cuckoo_solution: header.pow.proof.nonces.clone(),
			total_difficulty: header.pow.total_difficulty.to_num(),
			secondary_scaling: header.pow.secondary_scaling,
			total_kernel_offset: header.total_kernel_offset.to_hex(),
		}
	}
}

// Printable representation of a block
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockPrintable {
	/// The block header
	pub header: BlockHeaderPrintable,
	// Input transactions
	pub inputs: Vec<String>,
	/// A printable version of the outputs
	pub outputs: Vec<OutputPrintable>,
	/// A printable version of the transaction kernels
	pub kernels: Vec<TxKernelPrintable>,
}

impl BlockPrintable {
	pub fn from_block(
		block: &core::Block,
		chain: Arc<chain::Chain>,
		include_merkle_proof: bool,
	) -> Result<BlockPrintable, chain::Error> {
		let inputs = block
			.inputs()
			.iter()
			.map(|x| util::to_hex(x.commitment().0.to_vec()))
			.collect();
		let outputs = block
			.outputs()
			.iter()
			.map(|output| {
				OutputPrintable::from_output(
					output,
					chain.clone(),
					Some(&block.header),
					include_merkle_proof,
				)
			})
			.collect::<Result<Vec<_>, _>>()?;

		let kernels = block
			.kernels()
			.iter()
			.map(|kernel| TxKernelPrintable::from_txkernel(kernel))
			.collect();
		Ok(BlockPrintable {
			header: BlockHeaderPrintable::from_header(&block.header),
			inputs: inputs,
			outputs: outputs,
			kernels: kernels,
		})
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompactBlockPrintable {
	/// The block header
	pub header: BlockHeaderPrintable,
	/// Full outputs, specifically coinbase output(s)
	pub out_full: Vec<OutputPrintable>,
	/// Full kernels, specifically coinbase kernel(s)
	pub kern_full: Vec<TxKernelPrintable>,
	/// Kernels (hex short_ids)
	pub kern_ids: Vec<String>,
}

impl CompactBlockPrintable {
	/// Convert a compact block into a printable representation suitable for
	/// api response
	pub fn from_compact_block(
		cb: &core::CompactBlock,
		chain: Arc<chain::Chain>,
	) -> Result<CompactBlockPrintable, chain::Error> {
		let block = chain.get_block(&cb.hash())?;
		let out_full = cb
			.out_full()
			.iter()
			.map(|x| {
				OutputPrintable::from_output(x, chain.clone(), Some(&block.header), false)
			})
			.collect::<Result<Vec<_>, _>>()?;
		let kern_full = cb
			.kern_full()
			.iter()
			.map(|x| TxKernelPrintable::from_txkernel(x))
			.collect();
		Ok(CompactBlockPrintable {
			header: BlockHeaderPrintable::from_header(&cb.header),
			out_full,
			kern_full,
			kern_ids: cb.kern_ids().iter().map(|x| x.to_hex()).collect(),
		})
	}
}

// For wallet reconstruction, include the header info along with the
// transactions in the block
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockOutputs {
	/// The block header
	pub header: BlockHeaderInfo,
	/// A printable version of the outputs
	pub outputs: Vec<OutputPrintable>,
}

// For traversing all outputs in the UTXO set
// transactions in the block
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutputListing {
	/// The last available output index
	pub highest_index: u64,
	/// The last insertion index retrieved
	pub last_retrieved_index: u64,
	/// A printable version of the outputs
	pub outputs: Vec<OutputPrintable>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocatedTxKernel {
	pub tx_kernel: TxKernel,
	pub height: u64,
	pub mmr_index: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PoolInfo {
	/// Size of the pool
	pub pool_size: usize,
}

#[cfg(test)]
mod test {
	use super::*;
	use serde_json;

	#[test]
	fn serialize_output_printable() {
		let hex_output = r#"
			{
			  "output_type": "Coinbase",
			  "commit": "0897277036f04d54c85df2b8957e08167c37f35d2bb88248a10cf34a7043d97c30",
			  "spent": false,
			  "proof": null,
			  "proof_hash": "",
			  "block_height": 222796,
			  "merkle_proof": {
				"mmr_size": 600752,
				"path": [
				  "5c92c4a5d32186edb925dee9164d34947071fe33a42dc4b763a3d00f4f540c13",
				  "a49c9fa583b3438a829892f702fc8c284551ef7e4242d114c001bb567d916d57",
				  "f2793d2e68ded32ce5ddae56810bd0bdfe099e561c1599eb11d767fcac0d29ab",
				  "c50852c15f7a13f59c1e6bd0ad70b814c9236b0d05fb781b426a4a46f1813425",
				  "6f119eb0567b2efca31b60ad4a7ce97d567ed55d85cf0e71bc2a6ddc1e7359a2",
				  "0d8da5310beaa3d604dd06459b26b66551dd800416c0db28e0a14e3a29541dab",
				  "6399f2e3b77f6d3f1a1d1c4477c41b2830182bde020ef21c091dcbef8adbee70",
				  "002e329181899fa4b72be0502aa4e6d6b08fa6dd2526fb958a7e326f8974d983",
				  "49a49c6f7dbb41024f500ca1a8b2e118c4508d32345f33b4e913ff91110da8f6",
				  "211cf80c89de5b6bed3157ac4330cf88fb018b3c6d2c00f93781a60d280c68fb",
				  "a6d1f3c8d778dcd8861cc162c1c99c421654e601c67e3c36343685163aa6e5e4",
				  "14bda618f823948c7a1e6cdf4651eab5ce95d2afe31fed49d316ed924e3edf68",
				  "877c051e829ed8f44a355ad54938595b81bd73fe502e4f6e8a793299b45da5a2",
				  "13444cfddc56bdc98a9911b31731f2cad0218e55b53eeb054b5d843fa742f5dc"
				]
			  },
			  "mmr_index": 599956
			}
		"#;
		let output: OutputPrintable = serde_json::from_str(&hex_output).unwrap();
		let serialized = serde_json::to_string_pretty(&output).unwrap();
		println!("serialized OutputPrintable: {}", serialized);
		let deserialized_output: OutputPrintable = serde_json::from_str(&serialized).unwrap();
		assert_eq!(output, deserialized_output);
	}

	#[test]
	fn serialize_output() {
		let hex_commit =
			"{\
			 \"commit\":\"083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f\",\
			 \"height\":0,\
			 \"mmr_index\":0\
			 }";
		let deserialized: Output = serde_json::from_str(&hex_commit).unwrap();
		let serialized = serde_json::to_string(&deserialized).unwrap();
		assert_eq!(serialized, hex_commit);
	}
}
