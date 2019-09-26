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

//! Builds the blinded output and related signature proof for the block
//! reward.
use crate::consensus::reward;
use crate::core::{KernelFeatures, Output, OutputFeaturesEx, TxKernel};
use crate::keychain::{Identifier, Keychain};
use crate::libtx::aggsig;
use crate::libtx::error::Error;
use crate::libtx::proof::{self, ProofBuild};
use crate::util::{secp, static_secp_instance};

/// output a reward output
pub fn output<K, B>(
	keychain: &K,
	builder: &B,
	key_id: &Identifier,
	fees: u64,
	test_mode: bool,
) -> Result<(Output, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let value = reward(fees);
	let w = 0i64;
	let commit = keychain.commit(w, key_id)?;

	trace!("Block reward - Pedersen Commit is: {:?}", commit,);

	let spath = proof::create_secured_path(keychain, builder, w, &key_id, commit);

	let output = Output {
		features: OutputFeaturesEx::Coinbase { spath },
		commit,
		value,
	};

	let secp = static_secp_instance();
	let secp = secp.lock();
	let out_commit = output.commitment();
	let excess = out_commit;
	let pubkey = excess.to_pubkey(&secp)?;

	let features = KernelFeatures::Coinbase;
	let msg = features.kernel_sig_msg()?;
	let sig = match test_mode {
		true => {
			let test_nonce = secp::key::SecretKey::from_slice(&secp, &[1; 32])?;
			aggsig::sign_from_key_id(
				&secp,
				keychain,
				&msg,
				&key_id,
				Some(&test_nonce),
				Some(&pubkey),
			)?
		}
		false => aggsig::sign_from_key_id(&secp, keychain, &msg, &key_id, None, Some(&pubkey))?,
	};

	let proof = TxKernel {
		features: KernelFeatures::Coinbase,
		excess,
		excess_sig: sig,
	};
	Ok((output, proof))
}
