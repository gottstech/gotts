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

use std::fs::File;

use croaring::Bitmap;

use crate::core::hash::Hash;
use crate::core::pmmr;
use crate::core::BlockHeader;
use crate::ser::PMMRable;

/// Storage backend for the MMR, just needs to be indexed by order of insertion.
/// The PMMR itself does not need the Backend to be accurate on the existence
/// of an element (i.e. remove could be a no-op) but layers above can
/// depend on an accurate Backend to check existence.
pub trait Backend<T: PMMRable> {
	/// Append the provided Hashes to the backend storage, and optionally an
	/// associated data element to flatfile storage (for leaf nodes only). The
	/// position of the first element of the Vec in the MMR is provided to
	/// help the implementation.
	fn append(&mut self, data: &T, hashes: Vec<Hash>) -> Result<(), String>;

	/// Rewind the backend state to a previous position, as if all append
	/// operations after that had been canceled. Expects a position in the PMMR
	/// to rewind to as well as bitmaps representing the positions added and
	/// removed since the rewind position. These are what we will "undo"
	/// during the rewind.
	fn rewind(&mut self, position: u64, rewind_rm_pos: &Bitmap) -> Result<(), String>;

	/// Get a Hash by insertion position.
	fn get_hash(&self, position: u64) -> Option<Hash>;

	/// Get underlying data by insertion position.
	fn get_data(&self, position: u64) -> Option<T::E>;

	/// Get a Hash  by original insertion position
	/// (ignoring the remove log).
	fn get_from_file(&self, position: u64) -> Option<Hash>;

	/// Get a Data Element by original insertion position
	/// (ignoring the remove log).
	fn get_data_from_file(&self, position: u64) -> Option<T::E>;

	/// Iterator over current (unpruned, unremoved) leaf positions.
	fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_>;

	/// Remove Hash by insertion position. An index is also provided so the
	/// underlying backend can implement some rollback of positions up to a
	/// given index (practically the index is the height of a block that
	/// triggered removal).
	fn remove(&mut self, position: u64) -> Result<(), String>;

	/// Creates a temp file containing the contents of the underlying data file
	/// from the backend storage. This allows a caller to see a consistent view
	/// of the data without needing to lock the backend storage.
	fn data_as_temp_file(&self) -> Result<File, String>;

	/// Release underlying datafiles and locks
	fn release_files(&mut self);

	/// Saves a snapshot of the rewound utxo file with the block hash as
	/// filename suffix. We need this when sending a txhashset zip file to a
	/// node for fast sync.
	fn snapshot(&self, header: &BlockHeader) -> Result<(), String>;

	/// For debugging purposes so we can see how compaction is doing.
	fn dump_stats(&self);
}

/// Simple MMR backend implementation based on a Vector. Pruning does not
/// compact the Vec itself.
#[derive(Clone, Debug)]
pub struct VecBackend<T: PMMRable> {
	/// Backend elements
	pub data: Vec<T>,
	/// Hashes
	pub hashes: Vec<Hash>,
	/// Positions of removed elements
	pub remove_list: Vec<u64>,
}

impl<T: PMMRable> Backend<T> for VecBackend<T> {
	fn append(&mut self, data: &T, hashes: Vec<Hash>) -> Result<(), String> {
		self.data.push(data.clone());
		self.hashes.append(&mut hashes.clone());
		Ok(())
	}

	fn rewind(&mut self, position: u64, _rewind_rm_pos: &Bitmap) -> Result<(), String> {
		let idx = pmmr::n_leaves(position);
		self.data = self.data[0..(idx as usize) + 1].to_vec();
		self.hashes = self.hashes[0..(position as usize) + 1].to_vec();
		Ok(())
	}

	fn get_hash(&self, position: u64) -> Option<Hash> {
		if self.remove_list.contains(&position) {
			None
		} else {
			self.get_from_file(position)
		}
	}

	fn get_data(&self, position: u64) -> Option<T::E> {
		if self.remove_list.contains(&position) {
			None
		} else {
			self.get_data_from_file(position)
		}
	}

	fn get_from_file(&self, position: u64) -> Option<Hash> {
		let hash = &self.hashes[(position - 1) as usize];
		Some(hash.clone())
	}

	fn get_data_from_file(&self, position: u64) -> Option<T::E> {
		let idx = pmmr::n_leaves(position);
		let data = self.data[(idx - 1) as usize].clone();
		Some(data.as_elmt())
	}

	fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_> {
		unimplemented!()
	}

	fn remove(&mut self, position: u64) -> Result<(), String> {
		self.remove_list.push(position);
		Ok(())
	}

	fn data_as_temp_file(&self) -> Result<File, String> {
		unimplemented!()
	}

	fn release_files(&mut self) {}

	fn snapshot(&self, _header: &BlockHeader) -> Result<(), String> {
		Ok(())
	}

	fn dump_stats(&self) {}
}

impl<T: PMMRable> VecBackend<T> {
	/// Instantiates a new VecBackend<T>
	pub fn new() -> VecBackend<T> {
		VecBackend {
			data: vec![],
			hashes: vec![],
			remove_list: vec![],
		}
	}
}
