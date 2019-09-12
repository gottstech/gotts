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

/// Implements hex-encoding from bytes to string and decoding of strings to bytes.

/// Encode the provided bytes into a hex string.
#[inline]
pub fn to_hex(bytes: Vec<u8>) -> String {
	hex::encode(bytes)
}

/// Decode a hex string into bytes.
#[inline]
pub fn from_hex(hex_str: String) -> Result<Vec<u8>, hex::FromHexError> {
	hex::decode(hex_str)
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_to_hex() {
		assert_eq!(to_hex(vec![0, 0, 0, 0]), "00000000");
		assert_eq!(to_hex(vec![10, 11, 12, 13]), "0a0b0c0d");
		assert_eq!(to_hex(vec![0, 0, 0, 255]), "000000ff");
	}

	#[test]
	fn test_from_hex() {
		assert_eq!(from_hex("00000000".to_string()).unwrap(), vec![0, 0, 0, 0]);
		assert_eq!(
			from_hex("0a0b0c0d".to_string()).unwrap(),
			vec![10, 11, 12, 13]
		);
		assert_eq!(
			from_hex("000000ff".to_string()).unwrap(),
			vec![0, 0, 0, 255]
		);
	}
}
