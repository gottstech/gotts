// Copyright 2019 The Gotts Developers
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

//! Diff0 compress algorithm main code.
//! The purpose of this crate is to have an efficient compression algorithm for integer difference values
//! which has a lot of zeros, in case the difference is between some slow changing integer values.

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use failure::Fail;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

#[cfg(test)]
extern crate hex;

/// The size of a field to indicate the underlying original vector size.
/// (Note: can't change without tweaking the code)
pub const VECTOR_SIZE_LEN: usize = 2;

/// Diff0 compression, which is a diff0_compress_i64 firstly, and then a diff0_compress_u32 if it
/// indeed furtherly decrease the final size.
pub fn diff0_compress(diffs: Vec<i64>) -> Result<Vec<u8>, Error> {
	let data = diff0_compress_i64(diffs)?;
	let first_compressed_out_size = data.len();
	let data_2nd_compressed = diff0_compress_u32(data.clone())?;
	if data_2nd_compressed.len() < std::mem::size_of::<u32>() * first_compressed_out_size {
		Ok(data_2nd_compressed)
	} else {
		// convert Vec<u32> to Vec<u8>
		Ok(u32_to_u8(&data))
	}
}

/// Diff0 decompression. Depending on the indicator bit, it could be a diff0_decompress_i64 only,
/// or a diff0_decompress_i64 after a diff0_decompress_u32.
pub fn diff0_decompress(data: Vec<u8>) -> Result<Vec<i64>, Error> {
	if data.is_empty() {
		return Err(Error::InvalidLength);
	}

	// read the indicator to check whether there's a 2nd compression by 'diff0_compress_u8'.
	if data[0] >= 128u8 {
		let pre_decoded = diff0_decompress_u32(data)?;
		diff0_decompress_i64(pre_decoded)
	} else {
		let diffs = u8_to_u32(data)?;
		diff0_decompress_i64(diffs)
	}
}

/// Compression for vector i64.
/// Suppress 0x0000,0000 and 0xffff,ffff :
/// - bits '00' for i64 value 0,
/// - bits '01' for i64 in [00000000 || x],
/// - bits '10' for i64 in [ffffffff || x],
/// - bits '11' for i64 in others.
///
pub fn diff0_compress_i64(diffs: Vec<i64>) -> Result<Vec<u32>, Error> {
	if diffs.is_empty() {
		return Err(Error::InvalidLength);
	}
	let mut encoded: Vec<u32> = vec![];

	// encode the vector size
	let vec_size = diffs.len();
	if vec_size > (std::u16::MAX >> 1) as usize {
		return Err(Error::VectorTooLong);
	}

	// reserve the space to encode the flags and vector size
	let flags_bits = 2 * vec_size + 8 * VECTOR_SIZE_LEN;
	let mut flags_size = flags_bits >> 5;
	if (flags_bits & 31) != 0 {
		flags_size += 1; // 4 bytes alignment
	}
	for _ in 0..flags_size {
		encoded.push(0);
	}

	// encoding
	let mut enc_pos = 0;
	let mut flags = vec_size as u32;
	let mut bit_pos = 8 * VECTOR_SIZE_LEN as u32;
	for (i, diff) in diffs.iter().enumerate() {
		if *diff != 0 {
			// bits '00' for i64 value 0
			match *diff >> 32 {
				0 => {
					flags += 1 << bit_pos; // bits '01' for i64 in [00000000 || x]
					encoded.push(*diff as u32);
				}
				-1 => {
					flags += 2 << bit_pos; // bits '10' for i64 in [ffffffff || x]
					encoded.push(*diff as u32);
				}
				_ => {
					flags += 3 << bit_pos; // bits '11' for i64 in others
					encoded.push((*diff >> 32) as u32);
					encoded.push(*diff as u32);
				}
			}
		}
		bit_pos += 2;

		if bit_pos >= 32 || i == diffs.len() - 1 {
			encoded[enc_pos] = flags;
			enc_pos += 1;
			flags = 0u32;
			bit_pos = 0;
		}
	}

	// swap the first two u16 words for putting the indicator bit as the highest bit.
	// note: need tweak here if changing the VECTOR_SIZE_LEN.
	let left = (encoded[0] >> 16) as u16;
	let right = encoded[0] as u16;
	encoded[0] = ((right as u32) << 16) + left as u32;

	Ok(encoded)
}

/// Decompression for vector i64
pub fn diff0_decompress_i64(data: Vec<u32>) -> Result<Vec<i64>, Error> {
	// the highest bit of first word is used as the indicator of u32 compression.
	if !data.is_empty() && (data[0] & 0x80000000_u32) != 0 {
		return Err(Error::InvalidIndicator);
	}

	let mut diffs: Vec<i64> = vec![];

	// swap the first two u16 words
	let mut data = data.clone();
	let left = (data[0] >> 16) as u16;
	let right = data[0] as u16;
	data[0] = ((right as u32) << 16) + left as u32;

	// decode the output vector size
	let vec_size: u16 = data[0] as u16;

	// calculate the flags length
	let flags_bits = 2 * vec_size as usize + 8 * VECTOR_SIZE_LEN;
	let mut flags_size = flags_bits >> 5;
	if (flags_bits & 31) != 0 {
		flags_size += 1; // 4 bytes alignment
	}

	// pre-checking the compressed data length
	let mut len = flags_size;
	let mut dat_pos = 0;
	let mut bit_pos = 8 * VECTOR_SIZE_LEN as u32;
	for _ in (0..2 * vec_size).step(2) {
		len += match (data[dat_pos] >> bit_pos) & 3 {
			0 => 0,
			1 | 2 => 1,
			_ => 2,
		};
		bit_pos += 2;
		if bit_pos >= 32 {
			dat_pos += 1;
			bit_pos = 0;
		}
	}
	if data.len() != len {
		warn!("data length = {} but {} expected", data.len(), len);
		return Err(Error::CorruptedData);
	}

	// decoding
	let mut dif_pos = flags_size;
	let mut dat_pos = 0;
	let mut bit_pos = 8 * VECTOR_SIZE_LEN as u32;
	for _ in (0..2 * vec_size).step(2) {
		match (data[dat_pos] >> bit_pos) & 3 {
			0 => diffs.push(0),
			1 => {
				diffs.push(data[dif_pos] as i64);
				dif_pos += 1;
			}
			2 => {
				diffs.push(data[dif_pos] as i64 ^ (0xffffffff << 32));
				dif_pos += 1;
			}
			_ => {
				diffs.push(((data[dif_pos] as i64) << 32) ^ (data[dif_pos + 1] as i64));
				dif_pos += 2;
			}
		}
		bit_pos += 2;
		if bit_pos >= 32 {
			dat_pos += 1;
			bit_pos = 0;
		}
	}

	Ok(diffs)
}

/// Compression for vector u32.
/// Suppress 0x0000 and 0xffff :
/// - bits '00' for u32 value 0,
/// - bits '01' for u32 in [0000 || x],
/// - bits '10' for u32 in [ffff || x],
/// - bits '11' for u32 in others.
///
pub fn diff0_compress_u32(diffs: Vec<u32>) -> Result<Vec<u8>, Error> {
	if diffs.is_empty() {
		return Err(Error::InvalidLength);
	}
	let mut encoded: Vec<u8> = vec![];

	// encode the vector size
	let vec_size = diffs.len();
	if vec_size > (std::u16::MAX >> 1) as usize {
		return Err(Error::VectorTooLong);
	}
	// the highest bit of first byte is used as the indicator of u32 compression.
	encoded.push((vec_size >> 8) as u8 + 0x80_u8);
	encoded.push(vec_size as u8);

	// reserve the space to encode the flags, each 'u32' element uses 2 bits.
	let flags_bits = 2 * vec_size;
	let mut flags_bytes = flags_bits >> 3;
	if (flags_bits & 7) != 0 {
		flags_bytes += 1; // 8 bits alignment
	};
	for _ in 0..flags_bytes {
		encoded.push(0u8);
	}

	// encoding
	let mut enc_pos: usize = VECTOR_SIZE_LEN;
	let mut bit_pos: u8 = 0;
	let mut flags: u8 = 0;
	let mut bytes = [0u8; 4];
	for (i, diff) in diffs.iter().enumerate() {
		if *diff != 0 {
			// bits '00' for u32 value 0
			BigEndian::write_u32(&mut bytes, *diff);
			match *diff >> 16 {
				0 => {
					flags += 1 << bit_pos; // bits '01' for u32 in [0000 || x]
					encoded.append(&mut bytes[2..4].to_vec());
				}
				0xffffu32 => {
					flags += 2 << bit_pos; // bits '10' for u32 in [ffff || x]
					encoded.append(&mut bytes[2..4].to_vec());
				}
				_ => {
					flags += 3 << bit_pos; // bits '11' for u32 in others.
					encoded.append(&mut bytes.to_vec());
				}
			}
		}
		bit_pos += 2;

		if bit_pos >= 8 || i == diffs.len() - 1 {
			encoded[enc_pos] = flags;
			enc_pos += 1;
			flags = 0;
			bit_pos = 0;
		}
	}

	Ok(encoded)
}

/// Decompression for vector u32
pub fn diff0_decompress_u32(data: Vec<u8>) -> Result<Vec<u32>, Error> {
	// the highest bit of first byte is used as the indicator of u32 compression.
	if !data.is_empty() && data[0] < 0x80_u8 {
		return Err(Error::InvalidIndicator);
	}

	let mut diffs: Vec<u32> = vec![];
	if data.len() <= VECTOR_SIZE_LEN {
		return Err(Error::InvalidLength);
	}

	// decode the output vector size
	let vec_size: u16 = ((data[0] as u16 - 0x80_u16) << 8) + data[1] as u16;

	// calculate the flags length
	let flags_bits = 2 * vec_size;
	let mut flags_bytes = flags_bits >> 3;
	if (flags_bits & 7) != 0 {
		flags_bytes += 1; // 8 bits alignment
	};

	// pre-checking the compressed data length
	let mut len = VECTOR_SIZE_LEN + flags_bytes as usize;
	let mut enc_pos: usize = VECTOR_SIZE_LEN;
	let mut bit_pos: u8 = 0;
	for _ in (0..flags_bits).step(2) {
		len += match (data[enc_pos] >> bit_pos) & 3 {
			0 => 0,
			1 | 2 => 2,
			_ => 4,
		};
		bit_pos += 2;

		if bit_pos >= 8 {
			enc_pos += 1;
			bit_pos = 0;
		}
	}
	if data.len() != len {
		warn!("data length = {} but {} expected", data.len(), len);
		return Err(Error::CorruptedData);
	}

	// decoding
	let mut rdr = Cursor::new(data[2 + flags_bytes as usize..].to_vec());
	let mut enc_pos: usize = VECTOR_SIZE_LEN;
	let mut bit_pos: u8 = 0;
	for _ in (0..flags_bits).step(2) {
		match (data[enc_pos] >> bit_pos) & 3 {
			0 => diffs.push(0),
			1 => diffs.push(rdr.read_u16::<BigEndian>().unwrap() as u32),
			2 => diffs.push(rdr.read_u16::<BigEndian>().unwrap() as u32 ^ (0xffffu32 << 16)),
			_ => diffs.push(rdr.read_u32::<BigEndian>().unwrap()),
		}
		bit_pos += 2;

		if bit_pos >= 8 {
			enc_pos += 1;
			bit_pos = 0;
		}
	}

	Ok(diffs)
}

/// Util to convert Vec<u32> to Vec<u8>.
pub fn u32_to_u8(words: &Vec<u32>) -> Vec<u8> {
	let mut buffer = [0u8; 4];
	let mut bytes: Vec<u8> = Vec::with_capacity(std::mem::size_of::<u32>() * words.len());
	for word in words {
		BigEndian::write_u32(&mut buffer, *word);
		bytes.append(&mut buffer.to_vec());
	}
	bytes
}

/// Util to convert Vec<u8> to Vec<u32>.
pub fn u8_to_u32(bytes: Vec<u8>) -> Result<Vec<u32>, Error> {
	if bytes.is_empty() || (bytes.len() & 3) != 0 {
		return Err(Error::InvalidLength);
	}

	let size = bytes.len() >> 2;
	let mut words: Vec<u32> = Vec::with_capacity(size);
	let mut rdr = Cursor::new(bytes);
	for _ in 0..size {
		words.push(rdr.read_u32::<BigEndian>().unwrap());
	}
	Ok(words)
}

/// Error definition
#[derive(Clone, Eq, PartialEq, Debug, Fail, Serialize, Deserialize)]
pub enum Error {
	/// Vector too long
	#[fail(display = "Vector too long")]
	VectorTooLong,

	/// Invalid vector length
	#[fail(display = "Invalid vector length")]
	InvalidLength,

	/// Invalid indicator bit. The highest bit of vector length word is used as the indicator of u8 compression.
	#[fail(display = "Invalid indicator bit")]
	InvalidIndicator,

	/// Corrupted data
	#[fail(display = "Corrupted data")]
	CorruptedData,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn loopback_test_i64(values: Vec<i64>, expected_size: usize) {
		let serialized_buffer = diff0_compress_i64(values.clone()).unwrap();
		assert_eq!(serialized_buffer.len(), expected_size);
		let decoded_values = diff0_decompress_i64(serialized_buffer).unwrap();
		assert_eq!(decoded_values, values);
	}

	#[test]
	fn encoder_decoder_i64() {
		let diff_pairs: Vec<i64> = vec![
			100000,
			0,
			-2980000000,
			-40000000,
			0,
			0,
			0,
			3790000000,
			20000000,
			100000,
			0,
			-200000,
			0,
			-30000000,
			100000,
			0,
			-200000,
		];
		let sizes: Vec<usize> = vec![2, 2, 3, 4, 4, 4, 4, 5, 7, 8, 8, 9, 9, 10, 11, 11, 12];
		for i in 0..diff_pairs.len() {
			loopback_test_i64(diff_pairs[0..i + 1].to_vec(), sizes[i]);
		}

		let diff_pairs: Vec<i64> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
		let sizes: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18];
		for i in 0..diff_pairs.len() {
			loopback_test_i64(diff_pairs[0..i + 1].to_vec(), sizes[i]);
		}

		let diff_pairs: Vec<i64> = vec![0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8];
		let sizes: Vec<usize> = vec![1, 2, 2, 3, 3, 4, 4, 5, 6, 7, 7, 8, 8, 9, 9, 10];
		for i in 0..diff_pairs.len() {
			loopback_test_i64(diff_pairs[0..i + 1].to_vec(), sizes[i]);
		}
	}

	fn loopback_test_u32(data: Vec<u32>, expected_size: usize) {
		let serialized_buffer = diff0_compress_u32(data.clone()).unwrap();
		assert_eq!(serialized_buffer.len(), expected_size);
		let decoded_data = diff0_decompress_u32(serialized_buffer).unwrap();
		assert_eq!(decoded_data, data);
	}

	#[test]
	fn encoder_decoder_u32() {
		let raw_dat: Vec<u32> = vec![1, 0, 2, 3, 0, 0, 0, 4, 5, 6, 0, 7, 0, 8, 9, 0, 10];
		let sizes: Vec<usize> = vec![
			5, 5, 7, 9, 10, 10, 10, 12, 15, 17, 17, 19, 20, 22, 24, 24, 27,
		];

		let data = diff0_compress_u32(raw_dat.clone()).unwrap();
		println!("encoded data: {}", hex::encode(data.clone()));
		println!("decoded data: {:?}", diff0_decompress_u32(data).unwrap());

		for i in 0..raw_dat.len() {
			loopback_test_u32(raw_dat[0..i + 1].to_vec(), sizes[i]);
		}
	}

	fn loopback_test(values: Vec<i64>, expected_size: usize) {
		let serialized_buffer = diff0_compress(values.clone()).unwrap();
		assert_eq!(serialized_buffer.len(), expected_size);
		let decoded_values = diff0_decompress(serialized_buffer).unwrap();
		assert_eq!(decoded_values, values);
	}

	#[test]
	fn encoder_decoder() {
		let i64_pairs: Vec<i64> = vec![
			1110700000,
			1310200000,
			7936850000000,
			139920000000,
			6951000000,
			109280000000,
			1304400000,
		];
		loopback_test_i64(i64_pairs.clone(), 12);
		loopback_test(i64_pairs, 45);

		let diff_pairs: Vec<i64> = vec![0, 0, 5250000000, 40000000, 0, 0, 100000];
		loopback_test_i64(diff_pairs.clone(), 5);
		loopback_test(diff_pairs, 20);

		let diff_pairs: Vec<i64> = vec![100000, 0, -2980000000, -40000000, 0, 0, 0];
		loopback_test_i64(diff_pairs.clone(), 4);
		loopback_test(diff_pairs, 16);

		let diff_pairs: Vec<i64> = vec![0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8];
		loopback_test_i64(diff_pairs.clone(), 10);
		loopback_test(diff_pairs.clone(), 27);
		let serialized_buffer = diff0_compress_i64(diff_pairs.clone()).unwrap();
		println!("serialized data: {:08x?}", serialized_buffer);
		let serialized_buffer = diff0_compress(diff_pairs.clone()).unwrap();
		println!(
			"serialized len: {}, data: {}",
			serialized_buffer.len(),
			hex::encode(serialized_buffer)
		);

		// some edge cases
		let i64_pairs: Vec<i64> = vec![
			std::i64::MAX,
			0,
			-1,
			std::i64::MIN,
			0,
			-1,
			std::i64::MAX,
			std::i64::MIN,
		];
		loopback_test_i64(i64_pairs.clone(), 11);
		loopback_test(i64_pairs.clone(), 33);
		println!(
			"[max, 0, -1, min, 0, -1, max, min] serialized data: {}",
			hex::encode(diff0_compress(i64_pairs).unwrap())
		);

		// a 256 vector with a lot of zeros
		let mut lot_of_zeros: Vec<i64> = vec![];
		for i in 0..256 {
			if i % 32 == 0 {
				lot_of_zeros.push(i + 1);
			} else {
				lot_of_zeros.push(0);
			}
		}
		let serialized_buffer = diff0_compress(lot_of_zeros).unwrap();
		println!(
			"for a big vector with a lot of zeros, serialized len: {}, data: {}",
			serialized_buffer.len(),
			hex::encode(serialized_buffer)
		);
	}
}
