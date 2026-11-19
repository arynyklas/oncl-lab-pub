//! Streaming content ciphers of CMS `EnvelopedData` / `AuthEnvelopedData`: AES-CBC and
//! DES-EDE3-CBC (RFC 5652 / 3370 / 3565) and AES-GCM (RFC 5084).
//!
//! Every cipher works on bounded chunks: the caller feeds pieces of any size and gets the
//! output pieces back, so memory does not depend on the message size. AES-GCM is built from
//! CTR and GHASH as SP 800-38D defines it (one nonce, one message, one tag at the end): the
//! whole-buffer AEAD crates cannot take a 1 GiB message in pieces, and a nonce is never
//! reused for chunks.

use aes::cipher::{
    BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, InOutBuf, KeyInit, KeyIvInit,
    StreamCipher, typenum::Unsigned,
};
use aes::{Aes128, Aes192, Aes256};
use ctr::Ctr32BE;
use ghash::{GHash, universal_hash::UniversalHash};

/// Bytes of plaintext or ciphertext processed per step.
pub(super) const CHUNK: usize = 64 * 1024;

/// GCM encrypts at most `2^32 - 2` counter blocks (SP 800-38D 5.2.1.1): `2^36 - 32` bytes.
pub(super) const GCM_MAX_BYTES: u64 = (1 << 36) - 32;

/// The cipher failed: the data is not valid for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CipherError {
    /// Padding is wrong or the ciphertext is not a whole number of blocks.
    BadPadding,
    /// The authentication tag does not match.
    BadTag,
    /// The message is longer than the mode allows under one key and nonce.
    TooLong,
}

/// Encrypts a stream. `update` appends output to `out`, `finish` appends the rest and
/// returns the authentication tag (only AEAD modes have one).
pub(super) trait Encryptor {
    fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CipherError>;
    fn finish(self: Box<Self>, out: &mut Vec<u8>) -> Result<Option<[u8; 16]>, CipherError>;
}

/// Decrypts a stream. For an AEAD mode `finish` takes the received tag and compares it
/// (constant time) with the one computed; the output already handed out is then valid.
pub(super) trait Decryptor {
    fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CipherError>;
    fn finish(self: Box<Self>, out: &mut Vec<u8>, tag: Option<&[u8]>) -> Result<(), CipherError>;
}

pub(super) fn aes_cbc_encryptor(key: &[u8], iv: &[u8]) -> Option<Box<dyn Encryptor>> {
    match key.len() {
        16 => cbc_enc::<cbc::Encryptor<Aes128>>(key, iv),
        24 => cbc_enc::<cbc::Encryptor<Aes192>>(key, iv),
        32 => cbc_enc::<cbc::Encryptor<Aes256>>(key, iv),
        _ => None,
    }
}

pub(super) fn aes_cbc_decryptor(key: &[u8], iv: &[u8]) -> Option<Box<dyn Decryptor>> {
    match key.len() {
        16 => cbc_dec::<cbc::Decryptor<Aes128>>(key, iv),
        24 => cbc_dec::<cbc::Decryptor<Aes192>>(key, iv),
        32 => cbc_dec::<cbc::Decryptor<Aes256>>(key, iv),
        _ => None,
    }
}

pub(super) fn des_ede3_cbc_decryptor(key: &[u8], iv: &[u8]) -> Option<Box<dyn Decryptor>> {
    cbc_dec::<cbc::Decryptor<des::TdesEde3>>(key, iv)
}

fn cbc_enc<M: BlockModeEncrypt + KeyIvInit + 'static>(
    key: &[u8],
    iv: &[u8],
) -> Option<Box<dyn Encryptor>> {
    Some(Box::new(CbcEncrypt {
        mode: M::new_from_slices(key, iv).ok()?,
        pending: Vec::new(),
    }))
}

fn cbc_dec<M: BlockModeDecrypt + KeyIvInit + 'static>(
    key: &[u8],
    iv: &[u8],
) -> Option<Box<dyn Decryptor>> {
    Some(Box::new(CbcDecrypt {
        mode: M::new_from_slices(key, iv).ok()?,
        pending: Vec::new(),
    }))
}

struct CbcEncrypt<M> {
    mode: M,
    /// Fewer than one block of input not yet encrypted.
    pending: Vec<u8>,
}

impl<M: BlockModeEncrypt> CbcEncrypt<M> {
    fn encrypt_whole_blocks(&mut self, data: &mut [u8]) {
        let (blocks, rest) = InOutBuf::from(data).into_chunks();
        debug_assert!(rest.is_empty());
        self.mode.encrypt_blocks_inout(blocks);
    }
}

impl<M: BlockModeEncrypt> Encryptor for CbcEncrypt<M> {
    fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CipherError> {
        let start = out.len();
        out.extend_from_slice(&self.pending);
        out.extend_from_slice(input);
        let block = M::BlockSize::USIZE;
        let whole = start + ((out.len() - start) / block) * block;
        self.pending.clear();
        self.pending.extend_from_slice(&out[whole..]);
        out.truncate(whole);
        self.encrypt_whole_blocks(&mut out[start..]);
        Ok(())
    }

    fn finish(mut self: Box<Self>, out: &mut Vec<u8>) -> Result<Option<[u8; 16]>, CipherError> {
        let block = M::BlockSize::USIZE;
        let pad = block - self.pending.len();
        let start = out.len();
        out.extend_from_slice(&self.pending);
        // PKCS#7: pad bytes, each the pad length; a whole block when none is missing.
        out.resize(
            out.len() + pad,
            u8::try_from(pad).expect("a block is under 256 bytes"),
        );
        self.encrypt_whole_blocks(&mut out[start..]);
        Ok(None)
    }
}

struct CbcDecrypt<M> {
    mode: M,
    /// Input not yet decrypted: always the last 1..=16 bytes seen, because the last block
    /// carries the padding and is only known to be last at the end.
    pending: Vec<u8>,
}

impl<M: BlockModeDecrypt> CbcDecrypt<M> {
    fn decrypt_whole_blocks(&mut self, data: &mut [u8]) {
        let (blocks, rest) = InOutBuf::from(data).into_chunks();
        debug_assert!(rest.is_empty());
        self.mode.decrypt_blocks_inout(blocks);
    }
}

impl<M: BlockModeDecrypt> Decryptor for CbcDecrypt<M> {
    fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CipherError> {
        let block = M::BlockSize::USIZE;
        let start = out.len();
        out.extend_from_slice(&self.pending);
        out.extend_from_slice(input);
        let total = out.len() - start;
        // Keep 1..=block bytes back (nothing when there are none yet).
        let ready = if total == 0 {
            0
        } else {
            (total - 1) / block * block
        };
        let whole = start + ready;
        self.pending.clear();
        self.pending.extend_from_slice(&out[whole..]);
        out.truncate(whole);
        self.decrypt_whole_blocks(&mut out[start..]);
        Ok(())
    }

    fn finish(
        mut self: Box<Self>,
        out: &mut Vec<u8>,
        _tag: Option<&[u8]>,
    ) -> Result<(), CipherError> {
        let block = M::BlockSize::USIZE;
        if self.pending.len() != block {
            return Err(CipherError::BadPadding);
        }
        let mut last = std::mem::take(&mut self.pending);
        self.decrypt_whole_blocks(&mut last);
        let pad = usize::from(last[block - 1]);
        if pad == 0 || pad > block || last[block - pad..].iter().any(|&b| usize::from(b) != pad) {
            return Err(CipherError::BadPadding);
        }
        out.extend_from_slice(&last[..block - pad]);
        Ok(())
    }
}

/// AES-GCM with a 96-bit nonce, 128-bit key schedule size chosen by the key length.
pub(super) struct Gcm {
    ctr: Ctr,
    ghash: GHash,
    /// `E(K, J0)`, xored into the GHASH to make the tag.
    mask: [u8; 16],
    /// Ciphertext bytes not yet absorbed (less than one block).
    carry: [u8; 16],
    carry_len: usize,
    ciphertext_len: u64,
}

enum Ctr {
    A128(Ctr32BE<Aes128>),
    A192(Ctr32BE<Aes192>),
    A256(Ctr32BE<Aes256>),
}

impl Ctr {
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Ctr::A128(c) => c.apply_keystream(data),
            Ctr::A192(c) => c.apply_keystream(data),
            Ctr::A256(c) => c.apply_keystream(data),
        }
    }
}

impl Gcm {
    /// `None` if `key` is not a 128/192/256-bit AES key.
    pub(super) fn new(key: &[u8], nonce: &[u8; 12]) -> Option<Gcm> {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let mut counter = j0;
        counter[15] = 2;
        macro_rules! build {
            ($aes:ty, $variant:ident) => {{
                let cipher = <$aes>::new_from_slice(key).ok()?;
                let mut h = [0u8; 16].into();
                cipher.encrypt_block(&mut h);
                let mut mask = j0.into();
                cipher.encrypt_block(&mut mask);
                (
                    Ctr::$variant(Ctr32BE::<$aes>::new_from_slices(key, &counter).ok()?),
                    <[u8; 16]>::from(h),
                    <[u8; 16]>::from(mask),
                )
            }};
        }
        let (ctr, h, mask) = match key.len() {
            16 => build!(Aes128, A128),
            24 => build!(Aes192, A192),
            32 => build!(Aes256, A256),
            _ => return None,
        };
        Some(Gcm {
            ctr,
            ghash: GHash::new(&h.into()),
            mask,
            carry: [0; 16],
            carry_len: 0,
            ciphertext_len: 0,
        })
    }

    /// Feeds ciphertext to GHASH, whole blocks at a time.
    fn absorb(&mut self, mut data: &[u8]) -> Result<(), CipherError> {
        self.ciphertext_len = self
            .ciphertext_len
            .checked_add(data.len() as u64)
            .filter(|&n| n <= GCM_MAX_BYTES)
            .ok_or(CipherError::TooLong)?;
        if self.carry_len > 0 {
            let take = (16 - self.carry_len).min(data.len());
            self.carry[self.carry_len..self.carry_len + take].copy_from_slice(&data[..take]);
            self.carry_len += take;
            data = &data[take..];
            if self.carry_len < 16 {
                return Ok(());
            }
            self.ghash.update_padded(&self.carry);
            self.carry_len = 0;
        }
        let whole = data.len() / 16 * 16;
        if whole > 0 {
            self.ghash.update_padded(&data[..whole]);
        }
        let rest = &data[whole..];
        self.carry[..rest.len()].copy_from_slice(rest);
        self.carry_len = rest.len();
        Ok(())
    }

    fn tag(mut self) -> [u8; 16] {
        if self.carry_len > 0 {
            // Zero padding of the last partial block, as GHASH defines it.
            let carry = self.carry;
            self.ghash.update_padded(&carry[..self.carry_len]);
        }
        // No additional authenticated data: its length is zero.
        let mut lengths = [0u8; 16];
        lengths[8..].copy_from_slice(&(self.ciphertext_len * 8).to_be_bytes());
        self.ghash.update_padded(&lengths);
        let mut tag: [u8; 16] = self.ghash.finalize().into();
        for (t, m) in tag.iter_mut().zip(self.mask) {
            *t ^= m;
        }
        tag
    }
}

impl Encryptor for Gcm {
    fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CipherError> {
        let start = out.len();
        out.extend_from_slice(input);
        self.ctr.apply(&mut out[start..]);
        self.absorb(&out[start..])
    }

    fn finish(self: Box<Self>, _out: &mut Vec<u8>) -> Result<Option<[u8; 16]>, CipherError> {
        Ok(Some(self.tag()))
    }
}

impl Decryptor for Gcm {
    fn update(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CipherError> {
        self.absorb(input)?;
        let start = out.len();
        out.extend_from_slice(input);
        self.ctr.apply(&mut out[start..]);
        Ok(())
    }

    fn finish(self: Box<Self>, _out: &mut Vec<u8>, tag: Option<&[u8]>) -> Result<(), CipherError> {
        let expected = self.tag();
        let tag = tag.ok_or(CipherError::BadTag)?;
        // RFC 5084 allows 12..=16 byte tags; shorter ones are not a tag.
        if !(12..=16).contains(&tag.len()) {
            return Err(CipherError::BadTag);
        }
        // Fold every byte difference before deciding: no early exit on the first mismatch.
        let difference = expected[..tag.len()]
            .iter()
            .zip(tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if std::hint::black_box(difference) == 0 {
            Ok(())
        } else {
            Err(CipherError::BadTag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Encrypts `plaintext` in pieces of `step` bytes.
    fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8], step: usize) -> (Vec<u8>, [u8; 16]) {
        let mut gcm: Box<dyn Encryptor> =
            Box::new(Gcm::new(key, nonce.try_into().unwrap()).unwrap());
        let mut out = Vec::new();
        for piece in plaintext.chunks(step.max(1)) {
            gcm.update(piece, &mut out).unwrap();
        }
        let tag = gcm.finish(&mut out).unwrap().unwrap();
        (out, tag)
    }

    #[test]
    fn gcm_matches_the_gcm_specification_test_cases() {
        // Test cases 2, 3, 14 and 15 of "The Galois/Counter Mode of Operation" (McGrew,
        // Viega), and case 13 at the end: the cases without additional data (1-3 AES-128,
        // 13-15 AES-256); each in whole and in odd pieces, so that the partial-block carry
        // is exercised.
        let plaintext = hex(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        ));
        let cases = [
            (
                "00000000000000000000000000000000",
                "000000000000000000000000",
                vec![0u8; 16],
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (
                "feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                plaintext.clone(),
                concat!(
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
                    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
                ),
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000",
                vec![0u8; 16],
                "cea7403d4d606b6e074ec5d3baf39d18",
                "d0d1c8a799996bf0265b98b5d48ab919",
            ),
            (
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "cafebabefacedbaddecaf888",
                plaintext.clone(),
                concat!(
                    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
                    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
                ),
                "b094dac5d93471bdec1a502270e3cc6c",
            ),
        ];
        for (key, nonce, plaintext, ciphertext, tag) in cases {
            let (key, nonce) = (hex(key), hex(nonce));
            for step in [plaintext.len(), 1, 7, 16, 17] {
                let (sealed, actual) = seal(&key, &nonce, &plaintext, step);
                assert_eq!(sealed, hex(ciphertext), "ciphertext, pieces of {step}");
                assert_eq!(actual.to_vec(), hex(tag), "tag, pieces of {step}");
                let mut gcm: Box<dyn Decryptor> =
                    Box::new(Gcm::new(&key, nonce.as_slice().try_into().unwrap()).unwrap());
                let mut out = Vec::new();
                for piece in sealed.chunks(step) {
                    gcm.update(piece, &mut out).unwrap();
                }
                gcm.finish(&mut out, Some(&actual)).unwrap();
                assert_eq!(out, plaintext);
            }
        }
        // The empty message (test case 13, AES-256): the tag alone.
        let (sealed, tag) = seal(&[0; 32], &[0; 12], &[], 1);
        assert!(sealed.is_empty());
        assert_eq!(tag.to_vec(), hex("530f8afbc74536b9a963b4f1c4cb738b"));
    }

    #[test]
    fn gcm_rejects_a_wrong_tag_and_wrong_key_sizes() {
        let key = [3u8; 16];
        let (sealed, tag) = seal(&key, &[5; 12], b"authenticated", 4);
        for bad in [
            {
                let mut t = tag;
                t[15] ^= 1;
                t.to_vec()
            },
            tag[..8].to_vec(),
            Vec::new(),
        ] {
            let mut gcm: Box<dyn Decryptor> = Box::new(Gcm::new(&key, &[5; 12]).unwrap());
            let mut out = Vec::new();
            gcm.update(&sealed, &mut out).unwrap();
            assert_eq!(gcm.finish(&mut out, Some(&bad)), Err(CipherError::BadTag));
        }
        assert!(Gcm::new(&[0; 20], &[0; 12]).is_none());
    }

    #[test]
    fn cbc_matches_sp800_38a_and_pads_like_pkcs7() {
        // SP 800-38A F.2.1 (CBC-AES128), two blocks; the padding block follows.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let plaintext = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        ));
        let expected = hex(concat!(
            "7649abac8119b246cee98e9b12e9197d",
            "5086cb9b507219ee95db113a917678b2"
        ));
        for step in [32, 1, 5, 16] {
            let mut enc = aes_cbc_encryptor(&key, &iv).unwrap();
            let mut out = Vec::new();
            for piece in plaintext.chunks(step) {
                enc.update(piece, &mut out).unwrap();
            }
            enc.finish(&mut out).unwrap();
            assert_eq!(out.len(), 48, "a whole block of padding is added");
            assert_eq!(&out[..32], &expected[..], "pieces of {step}");
            let mut dec = aes_cbc_decryptor(&key, &iv).unwrap();
            let mut back = Vec::new();
            for piece in out.chunks(step) {
                dec.update(piece, &mut back).unwrap();
            }
            dec.finish(&mut back, None).unwrap();
            assert_eq!(back, plaintext);
        }
    }

    #[test]
    fn cbc_refuses_bad_padding_and_partial_blocks() {
        let key = [1u8; 32];
        let iv = [2u8; 16];
        let mut enc = aes_cbc_encryptor(&key, &iv).unwrap();
        let mut sealed = Vec::new();
        enc.update(b"0123456789abcdef!", &mut sealed).unwrap();
        enc.finish(&mut sealed).unwrap();
        let decrypt = |data: &[u8]| {
            let mut dec = aes_cbc_decryptor(&key, &iv).unwrap();
            let mut out = Vec::new();
            dec.update(data, &mut out).unwrap();
            dec.finish(&mut out, None)
        };
        assert_eq!(decrypt(&sealed), Ok(()));
        assert_eq!(
            decrypt(&sealed[..sealed.len() - 1]),
            Err(CipherError::BadPadding)
        );
        assert_eq!(decrypt(&[]), Err(CipherError::BadPadding));
        // A last block whose padding byte is 0 or longer than a block.
        for last in [0x00u8, 0x11] {
            let mut block = [0x41u8; 16];
            block[15] = last;
            let bad = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
                .unwrap()
                .encrypt_padded_vec::<aes::cipher::block_padding::NoPadding>(&block);
            assert_eq!(
                decrypt(&bad),
                Err(CipherError::BadPadding),
                "padding byte {last}"
            );
        }
    }
}
