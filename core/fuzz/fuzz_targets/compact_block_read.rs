#![no_main]
extern crate gotts_core;
#[macro_use]
extern crate libfuzzer_sys;

use gotts_core::core::CompactBlock;
use gotts_core::ser;

fuzz_target!(|data: &[u8]| {
	let mut d = data.clone();
	let _t: Result<CompactBlock, ser::Error> = ser::deserialize(&mut d);
});
