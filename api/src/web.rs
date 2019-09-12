use crate::rest::*;
use crate::router::ResponseFuture;
use futures::future::{err, ok};
use futures::{Future, Stream};
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fmt::Debug;
use url::form_urlencoded;

/// Parse request body
pub fn parse_body<T>(req: Request<Body>) -> Box<dyn Future<Item = T, Error = Error> + Send>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	Box::new(
		req.into_body()
			.concat2()
			.map_err(|e| ErrorKind::RequestError(format!("Failed to read request: {}", e)).into())
			.and_then(|body| match serde_json::from_reader(&body.to_vec()[..]) {
				Ok(obj) => ok(obj),
				Err(e) => {
					err(ErrorKind::RequestError(format!("Invalid request body: {}", e)).into())
				}
			}),
	)
}

/// Response on error
fn response_on_error(e: Error) -> ResponseFuture {
	match e.kind() {
		ErrorKind::Argument(msg) => response(StatusCode::BAD_REQUEST, msg.clone()),
		ErrorKind::RequestError(msg) => response(StatusCode::BAD_REQUEST, msg.clone()),
		ErrorKind::NotFound => response(StatusCode::NOT_FOUND, ""),
		ErrorKind::Internal(msg) => response(StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
		ErrorKind::ResponseError(msg) => response(StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
	}
}

/// Convert Result to ResponseFuture
pub fn result_to_response<T>(res: Result<T, Error>) -> ResponseFuture
where
	T: Serialize,
{
	match res {
		Ok(s) => json_response_pretty(&s),
		Err(e) => response_on_error(e),
	}
}

/// remove all newline and space in "cuckoo_solution" array
fn cuckoo_solution_force_pretty(string: &str) -> String {
	let split = string.split(r#""cuckoo_solution":"#);
	let mut parts: Vec<&str> = split.collect();
	if parts.len() != 2 {
		string.to_owned()
	} else {
		let remain = parts.pop().unwrap().to_owned();
		let mut result = parts.pop().unwrap().to_owned();
		if let Some(pos) = remain.chars().position(|c| c == ']') {
			let tail = &remain[pos..];
			let cuckoo_solution = String::from(&remain[0..pos]).replace(&['\n', ' '][..], "");
			result.push_str(r#""cuckoo_solution": "#);
			result.push_str(&cuckoo_solution);
			result.push_str(tail);
			result
		} else {
			string.to_owned()
		}
	}
}

/// Convert Result (with "cuckoo_solution" array) to ResponseFuture
pub fn result_with_cuckoo_solution_to_response<T>(res: Result<T, Error>) -> ResponseFuture
where
	T: Serialize,
{
	match res {
		Ok(s) => match serde_json::to_string_pretty(&s) {
			Ok(json) => response(StatusCode::OK, cuckoo_solution_force_pretty(&json)),
			Err(e) => response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("can't create json response: {}", e),
			),
		},
		Err(e) => response_on_error(e),
	}
}

/// Utility to serialize a struct into JSON and produce a sensible Response
/// out of it.
pub fn json_response<T>(s: &T) -> ResponseFuture
where
	T: Serialize,
{
	match serde_json::to_string(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

/// Pretty-printed version of json response as future
pub fn json_response_pretty<T>(s: &T) -> ResponseFuture
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(e) => response(
			StatusCode::INTERNAL_SERVER_ERROR,
			format!("can't create json response: {}", e),
		),
	}
}

/// Text response as HTTP response
pub fn just_response<T: Into<Body> + Debug>(status: StatusCode, text: T) -> Response<Body> {
	let mut resp = Response::new(text.into());
	*resp.status_mut() = status;
	resp
}

/// Text response as future
pub fn response<T: Into<Body> + Debug>(status: StatusCode, text: T) -> ResponseFuture {
	Box::new(ok(just_response(status, text)))
}

pub struct QueryParams {
	params: HashMap<String, Vec<String>>,
}

impl QueryParams {
	pub fn process_multival_param<F>(&self, name: &str, mut f: F)
	where
		F: FnMut(&str),
	{
		if let Some(ids) = self.params.get(name) {
			for id in ids {
				for id in id.split(',') {
					f(id);
				}
			}
		}
	}

	pub fn get(&self, name: &str) -> Option<&String> {
		match self.params.get(name) {
			None => None,
			Some(v) => v.first(),
		}
	}
}

impl From<&str> for QueryParams {
	fn from(query_string: &str) -> Self {
		let params = form_urlencoded::parse(query_string.as_bytes())
			.into_owned()
			.fold(HashMap::new(), |mut hm, (k, v)| {
				hm.entry(k).or_insert(vec![]).push(v);
				hm
			});
		QueryParams { params }
	}
}

impl From<Option<&str>> for QueryParams {
	fn from(query_string: Option<&str>) -> Self {
		match query_string {
			Some(query_string) => Self::from(query_string),
			None => QueryParams {
				params: HashMap::new(),
			},
		}
	}
}

impl From<Request<Body>> for QueryParams {
	fn from(req: Request<Body>) -> Self {
		Self::from(req.uri().query())
	}
}

#[macro_export]
macro_rules! right_path_element(
	($req: expr) =>(
		match $req.uri().path().trim_end_matches('/').rsplit('/').next() {
			None => return response(StatusCode::BAD_REQUEST, "invalid url"),
			Some(el) => el,
		};
	));

#[macro_export]
macro_rules! must_get_query(
	($req: expr) =>(
		match $req.uri().query() {
			Some(q) => q,
			None => return Err(ErrorKind::RequestError("no query string".to_owned()))?,
		}
	));

#[macro_export]
macro_rules! parse_param(
	($param: expr, $name: expr, $default: expr) =>(
	match $param.get($name) {
		None => $default,
		Some(val) =>  match val.parse() {
			Ok(val) => val,
			Err(_) => return Err(ErrorKind::RequestError(format!("invalid value of parameter {}", $name)))?,
		}
	}
	));

#[macro_export]
macro_rules! parse_param_no_err(
	($param: expr, $name: expr, $default: expr) =>(
	match $param.get($name) {
		None => $default,
		Some(val) =>  match val.parse() {
			Ok(val) => val,
			Err(_) => $default,
		}
	}
	));

#[macro_export]
macro_rules! w_fut(
	($p: expr) =>(
		match w($p) {
			Ok(p) => p,
			Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "weak reference upgrade failed" ),
		}
	));

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
	use super::*;
	use crate::BlockHeaderPrintable;
	use serde_json;

	#[test]
	fn test_cuckoo_solution_pretty() {
		let header_str = r#"
			{
			  "hash": "13f1512e696ebc9c398b3fdd5214be0ffe1925646a72b8655e34b9b444a0ff65",
			  "version": 2,
			  "height": 223187,
			  "previous": "0d6d7e9cadc9133bc00ff6be874bc54d2d625e28cadd883add65abea337f9c75",
			  "prev_root": "221528314aa9473ec29e0487f73a6b7a27d67d50fcba84b935ebcff548f052aa",
			  "timestamp": "2019-08-14T07:43:55+00:00",
			  "output_root": "02b7c0dd7a39534f4a277a8712d53dc6a7dcb8e880d44925c82644660ffb8ff8",
			  "range_proof_root": "9f47b51bedec333773acc05e10915c7637a9e93de49cd3cb36fa08fd2ce54ef9",
			  "kernel_root": "b2948fca468c10ae9913aece1cf90006964c195a7a390bf7ead1095e44443ee2",
			  "nonce": 171274901548211413,
			  "edge_bits": 29,
			  "cuckoo_solution": [
				11977075,
				12657902,
				37892432,
				66536092,
				111514571,
				118540632,
				121876188,
				137913397,
				156033810,
				161063857,
				168603151,
				170432171,
				174689091,
				188906919,
				220911228,
				222902925,
				225734076,
				226721496,
				234917267,
				265724164,
				267155688,
				274589373,
				278116363,
				295424279,
				325202541,
				352421506,
				372104233,
				394878658,
				405517447,
				418726413,
				435686970,
				436615810,
				439749960,
				454726776,
				454784984,
				465879075,
				477529937,
				486313182,
				489559063,
				493246423,
				498016786,
				532630302
			  ],
			  "total_difficulty": 16894227234,
			  "secondary_scaling": 13,
			  "total_kernel_offset": "b7486ea8ab0c428fe03aa274eac2cb783acd1a5b1042a6eebe12980f50e89390"
			}
		"#;
		let deserialized: BlockHeaderPrintable = serde_json::from_str(&header_str).unwrap();
		let pretty_header_str =
			cuckoo_solution_force_pretty(&serde_json::to_string_pretty(&deserialized).unwrap());
		println!(
			"the pretty header string with 'cuckoo_solution_force_pretty': {}",
			&pretty_header_str
		);
		let new_deserialized: BlockHeaderPrintable =
			serde_json::from_str(&pretty_header_str).unwrap();
		assert_eq!(new_deserialized, deserialized);
	}
}
