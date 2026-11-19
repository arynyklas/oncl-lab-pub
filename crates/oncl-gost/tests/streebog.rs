//! Published Streebog values through the public hashing of `oncl-gost` (the crates.io
//! `streebog`).
//!
//! Primary source: RFC 6986 §§4.2, 10.1, 10.2, complete Streebog bit-vector examples.
//! https://www.rfc-editor.org/rfc/rfc6986#section-10
//!
//! The secret-input Streebog and HMAC of the key agreement and the key wrap are crate-private;
//! their unit tests (`src/streebog_secret.rs`, `src/secret_hmac.rs`) check them against the
//! same RFC 6986 and RFC 7836 values and against the public path.

use streebog::{Digest, Streebog256, Streebog512};

fn hex(literal: &str) -> Vec<u8> {
    assert_eq!(literal.len() % 2, 0, "hex fixture must contain whole bytes");
    literal
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// The RFC prints a bit vector with the highest-numbered component on the
// left; RustCrypto consumes/returns byte strings in the opposite byte order.
// Reverse each COMPLETE decoded RFC message/digest once, never each block or
// word. This conversion does not call the implementation under test.
fn rfc6986_bytes(literal: &str) -> Vec<u8> {
    let mut bytes = hex(literal);
    bytes.reverse();
    bytes
}

const M1: &str = concat!(
    "32313039383736353433323130393837",
    "36353433323130393837363534333231",
    "30393837363534333231303938373635",
    "343332313039383736353433323130"
);
const M2: &str = concat!(
    "fbe2e5f0eee3c820fbeafaebef20fffb",
    "f0e1e0f0f520e0ed20e8ece0ebe5f0f2",
    "f120fff0eeec20f120faf2fee5e2202c",
    "e8f6f3ede220e8e6eee1e8f0f2d1202c",
    "e8f0f2e5e220e5d1"
);
const H256_M1: &str = concat!(
    "00557be5e584fd52a449b16b0251d05d",
    "27f94ab76cbaa6da890b59d8ef1e159d"
);
const H256_M2: &str = concat!(
    "508f7e553c06501d749a66fc28c6cac0",
    "b005746d97537fa85d9e40904efed29d"
);
const H512_M1: &str = concat!(
    "486f64c1917879417fef082b3381a4e2",
    "11c324f074654c38823a7b76f830ad00",
    "fa1fbae42b1285c0352f227524bc9ab1",
    "6254288dd6863dccd5b9f54a1ad0541b"
);
const H512_M2: &str = concat!(
    "28fbc9bada033b1460642bdcddb90c3f",
    "b3e56c497ccd0f62b8a2ad4935e85f03",
    "7613966de4ee00531ae60f3b5a47f8da",
    "e06915d5f2f194996fcabf2622e6881e"
);

fn published_digest<D: Digest + Clone>(message: &str, digest: &str, length: usize) {
    let input = rfc6986_bytes(message);
    let expected = rfc6986_bytes(digest);
    assert_eq!(input.len(), length, "published message length");
    // M1 is 63 bytes; M2 is 72 bytes and actually crosses the block boundary.
    // These detect dropped/reordered tails and full-block padding mistakes.
    for chunk_size in [1, 7, 31, 63, 64, 65] {
        let mut state = D::new();
        for chunk in input.chunks(chunk_size) {
            Digest::update(&mut state, chunk);
        }
        let actual = state.finalize();
        assert_eq!(&actual[..], expected.as_slice(), "chunk size {chunk_size}");
    }
    // Clone must copy the retained state AND the partial buffer.
    for split in [1, 63, 64, 65] {
        let split = split.min(input.len());
        let mut original = D::new();
        Digest::update(&mut original, &input[..split]);
        let mut cloned = original.clone();
        Digest::update(&mut original, &input[split..]);
        Digest::update(&mut cloned, &input[split..]);
        assert_eq!(
            &original.finalize()[..],
            expected.as_slice(),
            "original split {split}"
        );
        assert_eq!(
            &cloned.finalize()[..],
            expected.as_slice(),
            "clone split {split}"
        );
    }
}

#[test]
fn streebog256_rfc6986_examples() {
    for (message, digest, length) in [(M1, H256_M1, 63), (M2, H256_M2, 72)] {
        published_digest::<Streebog256>(message, digest, length);
        assert_eq!(
            oncl_gost::streebog256(&rfc6986_bytes(message)).as_slice(),
            rfc6986_bytes(digest).as_slice(),
            "oncl_gost::streebog256"
        );
    }
}

#[test]
fn streebog512_rfc6986_examples() {
    for (message, digest, length) in [(M1, H512_M1, 63), (M2, H512_M2, 72)] {
        published_digest::<Streebog512>(message, digest, length);
        assert_eq!(
            oncl_gost::streebog512(&rfc6986_bytes(message)).as_slice(),
            rfc6986_bytes(digest).as_slice(),
            "oncl_gost::streebog512"
        );
    }
}
