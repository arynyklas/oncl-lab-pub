// Derived from RustCrypto `streebog` 0.11.0 `src/block_api.rs` (MIT OR Apache-2.0; Copyright
// (c) 2016-2026 The RustCrypto Project Developers, Copyright (c) 2016 Artyom Pavlov; used here
// under Apache-2.0, see NOTICE). Modified for secret input as described below.

//! Streebog (GOST R 34.11-2012, RFC 6986) for secret input: the VKO shared point
//! ([`crate::agreement`]) and the key blocks of the KDF HMAC ([`crate::secret_hmac`]).
//!
//! Public documents are hashed by the crates.io `streebog` ([`crate::streebog256`],
//! [`crate::streebog512`]). This variant computes the same function; it comes from RustCrypto
//! `streebog` 0.11.0 (MIT OR Apache-2.0, see NOTICE) through the `secret-input` variant that
//! OpenNCALayer used to keep in a fork of that crate. It differs from the ordinary code in how
//! it treats the bytes it is given:
//!
//! - LPS never loads a table word at a secret index: it scans all 256 candidates of a row and
//!   picks one with `subtle` selection.
//! - Every compression temporary (message, round key, block, LPS accumulator, selector) lives in
//!   one workspace that is wiped after each block, after finalization and on drop.
//! - The whole state (chaining value, counter, checksum, partial block, workspace) is one heap
//!   allocation made before any input, so moving a hasher moves a pointer.
//! - The chaining value, counter, checksum and partial block are wiped as soon as the digest
//!   is written.
//!
//! This covers the memory the code owns. Copies the compiler keeps in registers or spills are
//! not covered; only a review of the optimized code can show those.

mod consts;

use consts::{BLOCK_SIZE, C64, SHUFFLED_LIN_TABLE};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Message bits of one full block, for the length counter `N`.
const BLOCK_BITS: u64 = 8 * BLOCK_SIZE as u64;

/// Borrowed storage that is wiped when the guard goes away, also on unwind. The storage stays
/// owned by the caller, so tests can check it after the guard is gone.
pub(crate) struct Wiped<'a, T: Zeroize>(&'a mut T);

impl<'a, T: Zeroize> Wiped<'a, T> {
    pub(crate) fn new(storage: &'a mut T) -> Self {
        Self(storage)
    }
}

impl<T: Zeroize> core::ops::Deref for Wiped<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Wiped<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}

impl<T: Zeroize> Drop for Wiped<'_, T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The one set of compression temporaries; it lives in the hasher's allocation.
struct Workspace {
    message: [u64; 8],
    key: [u64; 8],
    block: [u64; 8],
    lps: [u64; 8],
    /// The selected input byte and the candidate word picked for it.
    selector: [u64; 2],
}

impl Workspace {
    const ZERO: Self = Self {
        message: [0; 8],
        key: [0; 8],
        block: [0; 8],
        lps: [0; 8],
        selector: [0; 2],
    };

    fn clear(&mut self) {
        self.message.zeroize();
        self.key.zeroize();
        self.block.zeroize();
        self.lps.zeroize();
        self.selector.zeroize();
    }

    #[cfg(test)]
    fn is_clear(&self) -> bool {
        [self.message, self.key, self.block, self.lps]
            .iter()
            .all(|words| words.iter().all(|&word| word == 0))
            && self.selector == [0; 2]
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        self.clear();
    }
}

/// `h ^= n`, then the S, P and L transformations through the pre-shuffled table, without a
/// load at a secret index.
#[inline(always)]
fn lps(state: &mut [u64; 8], n: &[u64; 8], accumulator: &mut [u64; 8], selector: &mut [u64; 2]) {
    for (word, n) in state.iter_mut().zip(n) {
        *word ^= n;
    }
    let mut sum = Wiped::new(accumulator);
    sum.fill(0);
    let mut selected = Wiped::new(selector);
    for i in 0..8 {
        for (j, row) in SHUFFLED_LIN_TABLE.iter().enumerate() {
            // Reloading the source through a mutable reference and passing the selector and
            // the accumulator through `black_box` keeps them in the wiped workspace instead of
            // an eight-word copy in the frame (seen in the optimized x64 code of the fork).
            // This shapes the code; it does not guarantee the absence of spills.
            let source = core::hint::black_box(&mut *state);
            selected[0] = (source[j] >> (8 * i)) & 0xff;
            for (candidate, word) in row.iter().enumerate() {
                let selected = core::hint::black_box(&mut *selected);
                let choice = (candidate as u8).ct_eq(&(selected[0] as u8));
                selected[1] = u64::conditional_select(&0, word, choice);
                let sum = core::hint::black_box(&mut *sum);
                sum[i] ^= selected[1];
            }
        }
    }
    state.copy_from_slice(&*sum);
}

/// The compression function `g_N(h, m)`; `m` is `work.message`.
#[inline(always)]
fn g(h: &mut [u64; 8], n: &[u64; 8], work: &mut Workspace) {
    work.key.copy_from_slice(h);
    work.block.copy_from_slice(&work.message);
    lps(&mut work.key, n, &mut work.lps, &mut work.selector);
    for c in &C64 {
        lps(
            &mut work.block,
            &work.key,
            &mut work.lps,
            &mut work.selector,
        );
        lps(&mut work.key, c, &mut work.lps, &mut work.selector);
    }
    // Feed-forward from the workspace, not from a hoisted copy of it (an optimizer barrier on
    // the pointers, not a guarantee about spills).
    let work = core::hint::black_box(work);
    let h = core::hint::black_box(h);
    for (i, word) in h.iter_mut().enumerate() {
        *word ^= work.block[i] ^ work.key[i] ^ work.message[i];
    }
}

/// Add with carry, without a branch on the carry.
#[inline(always)]
fn adc(word: &mut u64, addend: u64, carry: &mut bool) {
    let (sum, first) = word.overflowing_add(addend);
    let (sum, second) = sum.overflowing_add(u64::from(*carry));
    *word = sum;
    *carry = first | second;
}

/// Chaining value `h`, message length counter `N` and checksum `Σ`.
struct Core {
    h: [u64; 8],
    n: [u64; 8],
    sigma: [u64; 8],
}

impl Core {
    /// Compresses one 64-byte block holding `bits` message bits and clears the workspace.
    fn compress(&mut self, block: &[u8; BLOCK_SIZE], bits: u64, work: &mut Workspace) {
        for (word, bytes) in work.message.iter_mut().zip(block.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*bytes);
        }
        g(&mut self.h, &self.n, work);
        let mut carry = false;
        adc(&mut self.n[0], bits, &mut carry);
        for word in &mut self.n[1..] {
            adc(word, 0, &mut carry);
        }
        let mut carry = false;
        for (word, &message) in self.sigma.iter_mut().zip(&work.message) {
            adc(word, message, &mut carry);
        }
        work.clear();
    }

    fn clear(&mut self) {
        self.h.zeroize();
        self.n.zeroize();
        self.sigma.zeroize();
    }
}

/// Everything a hasher holds, in one allocation.
struct State {
    core: Core,
    /// Partial block: `pos` bytes, always fewer than 64 (a full block is compressed at once);
    /// the bytes after `pos` are zero.
    buffer: [u8; BLOCK_SIZE],
    pos: usize,
    work: Workspace,
}

impl Drop for State {
    fn drop(&mut self) {
        self.core.clear();
        self.buffer.zeroize();
        self.pos = 0;
        // `work` wipes itself when it is dropped next.
    }
}

/// Streebog with an `N`-byte digest (32 or 64) for secret input. No `Clone`, `Debug` or
/// serialized state.
pub(crate) struct SecretStreebog<const N: usize> {
    state: Box<State>,
}

/// Streebog-256 for secret input.
pub(crate) type Streebog256Secret = SecretStreebog<32>;
/// Streebog-512 for secret input.
pub(crate) type Streebog512Secret = SecretStreebog<64>;

impl<const N: usize> SecretStreebog<N> {
    /// Initial chaining value word (GOST R 34.11-2012 §5.1, §8.1).
    const IV: u64 = {
        assert!(
            N == 32 || N == 64,
            "Streebog has 256- and 512-bit digests only"
        );
        if N == 32 { 0x0101_0101_0101_0101 } else { 0 }
    };

    /// Allocates the state; nothing secret exists yet, so this by-value construction is the
    /// only one.
    pub(crate) fn new() -> Self {
        Self {
            state: Box::new(State {
                core: Core {
                    h: [Self::IV; 8],
                    n: [0; 8],
                    sigma: [0; 8],
                },
                buffer: [0; BLOCK_SIZE],
                pos: 0,
                work: Workspace::ZERO,
            }),
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        let State {
            core,
            buffer,
            pos,
            work,
        } = &mut *self.state;
        if *pos > 0 {
            let take = (BLOCK_SIZE - *pos).min(input.len());
            let (head, rest) = input.split_at(take);
            buffer[*pos..*pos + take].copy_from_slice(head);
            *pos += take;
            input = rest;
            if *pos < BLOCK_SIZE {
                return;
            }
            core.compress(buffer, BLOCK_BITS, work);
            buffer.zeroize();
            *pos = 0;
        }
        let (blocks, tail) = input.as_chunks::<BLOCK_SIZE>();
        for block in blocks {
            core.compress(block, BLOCK_BITS, work);
        }
        buffer[..tail.len()].copy_from_slice(tail);
        *pos = tail.len();
    }

    /// Writes the digest and wipes the state.
    pub(crate) fn finalize_into(mut self, out: &mut [u8; N]) {
        self.finish(out);
    }

    /// Finalization proper; leaves every owned buffer zero (checked by the tests).
    fn finish(&mut self, out: &mut [u8; N]) {
        let State {
            core,
            buffer,
            pos,
            work,
        } = &mut *self.state;
        // Pad the last (possibly empty) partial block with a single 1 bit.
        buffer[*pos + 1..].fill(0);
        buffer[*pos] = 1;
        core.compress(buffer, 8 * *pos as u64, work);
        buffer.zeroize();
        *pos = 0;
        work.message.copy_from_slice(&core.n);
        g(&mut core.h, &[0; 8], work);
        work.clear();
        work.message.copy_from_slice(&core.sigma);
        g(&mut core.h, &[0; 8], work);
        work.clear();
        // The digest is the last N bytes of the little-endian h (truncation on the right).
        for (i, byte) in out.iter_mut().enumerate() {
            let index = BLOCK_SIZE - N + i;
            *byte = (core.h[index / 8] >> (8 * (index % 8))) as u8;
        }
        core.clear();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretStreebog<N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use streebog::Digest;

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

    // RFC 6986 prints a bit vector with the highest-numbered component on the left; the
    // implementations take and return byte strings in the opposite order. Each COMPLETE decoded
    // message/digest is reversed once, never per block or word.
    fn rfc6986_bytes(literal: &str) -> Vec<u8> {
        let mut bytes = hex(literal);
        bytes.reverse();
        bytes
    }

    // RFC 6986 §10.1 (M1, 63 bytes) and §10.2 (M2, 72 bytes: crosses a block boundary).
    // https://www.rfc-editor.org/rfc/rfc6986#section-10
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

    fn secret_digest<const N: usize>(chunks: &mut dyn Iterator<Item = &[u8]>) -> [u8; N] {
        let mut state = SecretStreebog::<N>::new();
        for chunk in chunks {
            state.update(chunk);
        }
        let mut out = [0; N];
        state.finalize_into(&mut out);
        out
    }

    /// The secret and the public (crates.io) Streebog give the published digest, whole and
    /// fed in chunks that split and cross the 64-byte blocks.
    fn published<const N: usize, D: Digest>(message: &str, digest: &str, length: usize) {
        let input = rfc6986_bytes(message);
        let expected = rfc6986_bytes(digest);
        assert_eq!(input.len(), length, "published message length");
        assert_eq!(expected.len(), N, "published digest length");
        assert_eq!(&D::digest(&input)[..], expected.as_slice(), "public path");
        for chunk_size in [1, 7, 31, 63, 64, 65, 200] {
            let actual = secret_digest::<N>(&mut input.chunks(chunk_size));
            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn streebog256_rfc6986_examples() {
        published::<32, streebog::Streebog256>(M1, H256_M1, 63);
        published::<32, streebog::Streebog256>(M2, H256_M2, 72);
    }

    #[test]
    fn streebog512_rfc6986_examples() {
        published::<64, streebog::Streebog512>(M1, H512_M1, 63);
        published::<64, streebog::Streebog512>(M2, H512_M2, 72);
    }

    #[test]
    fn secret_and_public_paths_agree_on_every_length_up_to_three_blocks() {
        let data: Vec<u8> = (0..=200u32)
            .map(|i| (i.wrapping_mul(167) ^ 0x5a) as u8)
            .collect();
        for length in 0..data.len() {
            let message = &data[..length];
            let split = length / 3;
            let (first, second) = message.split_at(split);
            assert_eq!(
                secret_digest::<32>(&mut [first, second].into_iter()).as_slice(),
                &streebog::Streebog256::digest(message)[..],
                "Streebog-256, {length} bytes"
            );
            assert_eq!(
                secret_digest::<64>(&mut [first, second].into_iter()).as_slice(),
                &streebog::Streebog512::digest(message)[..],
                "Streebog-512, {length} bytes"
            );
        }
    }

    #[test]
    fn length_counter_carries_into_the_top_word() {
        let mut core = Core {
            h: [0; 8],
            n: [
                u64::MAX - 511,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                0,
            ],
            sigma: [0; 8],
        };
        let mut work = Workspace::ZERO;
        core.compress(&[0; BLOCK_SIZE], BLOCK_BITS, &mut work);
        assert_eq!(core.n, [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn workspace_is_wiped_after_each_block_and_partial_input() {
        let mut state = Streebog256Secret::new();
        state.update(&[0xa5; 64]);
        assert!(state.state.work.is_clear(), "after a full block");
        assert_eq!(state.state.pos, 0);
        state.update(&[0x5a; 100]);
        assert!(state.state.work.is_clear(), "after a block and a tail");
        assert_eq!(state.state.pos, 36);
        state.update(&[0x3c; 28]);
        assert!(
            state.state.work.is_clear(),
            "after completing a buffered block"
        );
        assert_eq!(state.state.pos, 0);
        assert_eq!(state.state.buffer, [0; BLOCK_SIZE], "compressed buffer");
    }

    #[test]
    fn finish_wipes_chaining_value_counter_checksum_buffer_and_workspace() {
        let input = rfc6986_bytes(M2);
        let mut state = Streebog512Secret::new();
        state.update(&input);
        assert_ne!(state.state.pos, 0, "M2 leaves a partial block");
        let mut out = [0; 64];
        state.finish(&mut out);
        assert_eq!(out.as_slice(), rfc6986_bytes(H512_M2).as_slice());
        let State {
            core,
            buffer,
            pos,
            work,
        } = &*state.state;
        assert_eq!(core.h, [0; 8], "chaining value");
        assert_eq!(core.n, [0; 8], "length counter");
        assert_eq!(core.sigma, [0; 8], "checksum");
        assert_eq!(*buffer, [0; BLOCK_SIZE], "partial block");
        assert_eq!(*pos, 0);
        assert!(work.is_clear(), "workspace");
    }

    #[test]
    fn workspace_clear_covers_every_field() {
        let mut work = Workspace {
            message: [1; 8],
            key: [2; 8],
            block: [3; 8],
            lps: [4; 8],
            selector: [0xab, 0xfedc_ba98_7654_3210],
        };
        work.clear();
        assert!(work.is_clear());
    }

    #[test]
    fn wiped_guard_wipes_on_drop() {
        let mut words = [u64::MAX; 8];
        {
            let _guard = Wiped::new(&mut words);
        }
        assert_eq!(words, [0; 8]);
        let mut bytes = [0x5c_u8; 64];
        {
            let _guard = Wiped::new(&mut bytes);
        }
        assert_eq!(bytes, [0; 64]);
    }

    #[test]
    fn wiped_guard_wipes_on_unwind() {
        let mut selector: [u64; 2] = [0xab, 0xfedc_ba98_7654_3210];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = Wiped::new(&mut selector);
            panic!("synthetic unwind");
        }));
        assert!(result.is_err());
        assert_eq!(selector, [0; 2]);
    }

    #[test]
    fn secret_hashers_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Streebog256Secret>();
        assert_zeroize_on_drop::<Streebog512Secret>();
    }
}
