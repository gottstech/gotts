#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate gotts_core;
extern crate gotts_p2p;

use gotts_core::ser;
use gotts_p2p::msg::Locator;

fuzz_target!(|data: &[u8]| {
	let mut d = data.clone();
	let _t: Result<Locator, ser::Error> = ser::deserialize(&mut d);
});
