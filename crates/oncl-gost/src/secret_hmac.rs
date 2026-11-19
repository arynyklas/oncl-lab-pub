//! RFC 2104 HMAC over the secret Streebog ([`crate::streebog_secret`]):
//! HMAC_GOSTR3411_2012_256/512 of RFC 7836 §4.1.1, for the KDF of [`crate::wrap`].
//!
//! Ordinary HMAC (PKCS#12 MACs, PBKDF2) is the crates.io `hmac`. This one keeps what the HMAC
//! derives from the key in memory it wipes, also on unwind: the normalized key block (`K ⊕
//! ipad`, then `K ⊕ opad`), the hash of a key longer than a block and the inner digest. The
//! keyed hash states are the boxed secret Streebog states, so moving a `SecretHmac` moves two
//! pointers.

use crate::streebog_secret::{SecretStreebog, Wiped};
use zeroize::ZeroizeOnDrop;

/// Streebog block size, the HMAC `B`.
const BLOCK: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// HMAC with Streebog of an `N`-byte digest (32 or 64). No `Clone`, `Debug` or reset.
pub(crate) struct SecretHmac<const N: usize> {
    inner: SecretStreebog<N>,
    outer: SecretStreebog<N>,
}

impl<const N: usize> SecretHmac<N> {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self::new_in(key, &mut [0u8; BLOCK])
    }

    /// Keys the HMAC through `storage`, which is wiped before this returns (also on unwind).
    fn new_in(key: &[u8], storage: &mut [u8; BLOCK]) -> Self {
        // Both states are allocated before any key byte is copied anywhere.
        let mut inner = SecretStreebog::<N>::new();
        let mut outer = SecretStreebog::<N>::new();
        let mut block = Wiped::new(storage);
        block.fill(0);
        if key.len() > BLOCK {
            // A key longer than the block is replaced by its hash, written straight into the
            // wiped block.
            let mut hash = SecretStreebog::<N>::new();
            hash.update(key);
            let head = block
                .first_chunk_mut::<N>()
                .expect("a Streebog digest fits in its block");
            hash.finalize_into(head);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        for byte in block.iter_mut() {
            *byte ^= IPAD;
        }
        inner.update(&block[..]);
        for byte in block.iter_mut() {
            *byte ^= IPAD ^ OPAD;
        }
        outer.update(&block[..]);
        Self { inner, outer }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub(crate) fn finalize_into(self, out: &mut [u8; N]) {
        self.finalize_in(out, &mut [0u8; N]);
    }

    /// Finalizes with the inner digest in `storage`, which is wiped before this returns.
    fn finalize_in(self, out: &mut [u8; N], storage: &mut [u8; N]) {
        let Self { inner, mut outer } = self;
        let mut digest = Wiped::new(storage);
        inner.finalize_into(&mut digest);
        outer.update(&digest[..]);
        outer.finalize_into(out);
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretHmac<N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};

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

    // RFC 7836 Appendix B, examples 1 and 2. The RFC prints these as byte strings: DO NOT
    // reverse them. The message is also the exact RFC 7836 §4.5 KDF input for label 26bdb878,
    // seed af21434145656378 and L = 256 (the KDF test of `wrap`).
    // https://www.rfc-editor.org/rfc/rfc7836#appendix-B
    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const MESSAGE: &str = "0126bdb87800af214341456563780100";
    const HMAC256: &str = concat!(
        "a1aa5f7de402d7b3d323f2991c8d4534",
        "013137010a83754fd0af6d7cd4922ed9"
    );
    const HMAC512: &str = concat!(
        "a59bab22ecae19c65fbde6e5f4e9f5d8",
        "549d31f037f9df9b905500e171923a77",
        "3d5f1530f2ed7e964cb2eedc29e9ad2f",
        "3afe93b2814f79f5000ffc0366c251e6"
    );

    fn secret<const N: usize>(key: &[u8], message: &[u8], chunk_size: usize) -> [u8; N] {
        let mut mac = SecretHmac::<N>::new(key);
        for chunk in message.chunks(chunk_size) {
            mac.update(chunk);
        }
        let mut out = [0; N];
        mac.finalize_into(&mut out);
        out
    }

    fn public256(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<streebog::Streebog256> as KeyInit>::new_from_slice(key).unwrap();
        Mac::update(&mut mac, message);
        mac.finalize().into_bytes().to_vec()
    }

    fn public512(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<streebog::Streebog512> as KeyInit>::new_from_slice(key).unwrap();
        Mac::update(&mut mac, message);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn hmac256_rfc7836_example_1() {
        let (key, message, expected) = (hex(KEY), hex(MESSAGE), hex(HMAC256));
        assert_eq!(public256(&key, &message), expected, "public path");
        for chunk_size in [1, 7, 15, 16, 17] {
            let actual = secret::<32>(&key, &message, chunk_size);
            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn hmac512_rfc7836_example_2() {
        let (key, message, expected) = (hex(KEY), hex(MESSAGE), hex(HMAC512));
        assert_eq!(public512(&key, &message), expected, "public path");
        for chunk_size in [1, 7, 15, 16, 17] {
            let actual = secret::<64>(&key, &message, chunk_size);
            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn secret_and_public_paths_agree_on_short_block_and_long_keys() {
        let data: Vec<u8> = (0..300u32)
            .map(|i| (i.wrapping_mul(193) ^ 0xa7) as u8)
            .collect();
        // 65 and more bytes take the long-key branch (the key is hashed first).
        for key_length in [0, 1, 32, 63, 64, 65, 100, 200] {
            let key = &data[..key_length];
            for message_length in [0, 1, 63, 64, 65, 150] {
                let message = &data[100..100 + message_length];
                assert_eq!(
                    secret::<32>(key, message, 13).as_slice(),
                    public256(key, message).as_slice(),
                    "HMAC-Streebog-256, key {key_length}, message {message_length}"
                );
                assert_eq!(
                    secret::<64>(key, message, 13).as_slice(),
                    public512(key, message).as_slice(),
                    "HMAC-Streebog-512, key {key_length}, message {message_length}"
                );
            }
        }
    }

    #[test]
    fn secret_hmacs_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretHmac<32>>();
        assert_zeroize_on_drop::<SecretHmac<64>>();
    }

    #[test]
    fn key_block_storage_is_wiped_after_keying() {
        // Short key (copied) and long key (its hash written into the block), both widths.
        let long = [0xa7_u8; 100];
        for key in [&[0x5c_u8; 32][..], &long[..]] {
            let mut storage = [0xff_u8; BLOCK];
            let mac = SecretHmac::<32>::new_in(key, &mut storage);
            assert_eq!(storage, [0; BLOCK], "256, key {} bytes", key.len());
            let mut out = [0; 32];
            mac.finalize_into(&mut out);
            assert_eq!(out.as_slice(), public256(key, b"").as_slice());
            let mut storage = [0xff_u8; BLOCK];
            let mac = SecretHmac::<64>::new_in(key, &mut storage);
            assert_eq!(storage, [0; BLOCK], "512, key {} bytes", key.len());
            let mut out = [0; 64];
            mac.finalize_into(&mut out);
            assert_eq!(out.as_slice(), public512(key, b"").as_slice());
        }
    }

    #[test]
    fn inner_digest_storage_is_wiped_after_finalization() {
        let (key, message) = (hex(KEY), hex(MESSAGE));
        let mut mac = SecretHmac::<32>::new(&key);
        mac.update(&message);
        let mut storage = [0xff_u8; 32];
        let mut out = [0; 32];
        mac.finalize_in(&mut out, &mut storage);
        assert_eq!(storage, [0; 32]);
        assert_eq!(out.as_slice(), hex(HMAC256).as_slice());
        let mut mac = SecretHmac::<64>::new(&key);
        mac.update(&message);
        let mut storage = [0xff_u8; 64];
        let mut out = [0; 64];
        mac.finalize_in(&mut out, &mut storage);
        assert_eq!(storage, [0; 64]);
        assert_eq!(out.as_slice(), hex(HMAC512).as_slice());
    }
}
