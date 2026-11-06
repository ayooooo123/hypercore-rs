//! Hypercore 11 block encryption, a port of `hypercore/lib/default-encryption.js`.
//!
//! A stored block is [`PADDING`] bytes of blinded fork id followed by the
//! plaintext; both halves are encrypted in place with XSalsa20.

use salsa20::XSalsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher};

use crate::crypto;

/// Bytes of encrypted padding in front of every block.
pub const PADDING: usize = 8;

/// How the encryption key is turned into the block key.
#[derive(Default, Clone, Copy)]
pub struct EncryptionOptions {
    /// The key already is the block key, as produced by
    /// [`BlockEncryption::block_encryption_key`]; `hypercore_key` is then unused.
    pub block: bool,
    /// Pre-manifest core: key the derivation with the hypercore key instead of the
    /// `DEFAULT_ENCRYPTION` namespace.
    pub compat: bool,
}

/// Block cipher state for one core and one encryption key.
pub struct BlockEncryption {
    block_key: [u8; 32],
    blinding_key: [u8; 32],
}

impl BlockEncryption {
    /// `encryption_key` is the shared key, `hypercore_key` the core key.
    pub fn new(
        encryption_key: &[u8; 32],
        hypercore_key: &[u8; 32],
        opts: EncryptionOptions,
    ) -> Self {
        let block_key = if opts.block {
            *encryption_key
        } else if opts.compat {
            crypto::keyed_hash(hypercore_key, &[encryption_key])
        } else {
            Self::block_encryption_key(hypercore_key, encryption_key)
        };

        Self {
            block_key,
            blinding_key: crypto::hash(&[&block_key]),
        }
    }

    /// Derives a key that is used as-is when constructing with `block: true`.
    pub fn block_encryption_key(hypercore_key: &[u8; 32], encryption_key: &[u8; 32]) -> [u8; 32] {
        crypto::hash(&[
            &crypto::default_encryption_namespace(),
            hypercore_key,
            encryption_key,
        ])
    }

    /// XSalsa20 key for block contents.
    pub fn block_key(&self) -> &[u8; 32] {
        &self.block_key
    }

    /// Key the fork id in the padding is blinded with.
    pub fn blinding_key(&self) -> &[u8; 32] {
        &self.blinding_key
    }

    /// Encrypts a block of [`PADDING`] padding bytes followed by plaintext, in place.
    /// Panics if `block` is shorter than [`PADDING`].
    pub fn encrypt(&self, index: u64, block: &mut [u8], fork: u64) {
        let (padding, data) = split(block);
        padding.copy_from_slice(&fork.to_le_bytes());

        let mut cipher = XSalsa20::new(
            &self.blinding_key.into(),
            &nonce(index, &[0; PADDING]).into(),
        );
        cipher.apply_keystream(padding);

        // The blinded fork id doubles as the nonce tail: (index, fork) is the nonce.
        let mut cipher = XSalsa20::new(&self.block_key.into(), &nonce(index, padding).into());
        cipher.apply_keystream(data);
    }

    /// In-place inverse of [`encrypt`](Self::encrypt) for the same index; the
    /// plaintext is `block[PADDING..]` afterwards and the padding stays encrypted.
    /// Panics if `block` is shorter than [`PADDING`].
    pub fn decrypt(&self, index: u64, block: &mut [u8]) {
        let (padding, data) = split(block);

        let mut cipher = XSalsa20::new(&self.block_key.into(), &nonce(index, padding).into());
        cipher.apply_keystream(data);
    }

    /// Bytes of padding prepended to each block.
    pub fn padding(&self) -> usize {
        PADDING
    }
}

/// `index` little-endian, then the (blinded) fork id, zero padded to 24 bytes.
fn nonce(index: u64, padding: &[u8]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&index.to_le_bytes());
    nonce[8..16].copy_from_slice(padding);
    nonce
}

fn split(block: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    assert!(
        block.len() >= PADDING,
        "block shorter than the padding prefix"
    );
    block.split_at_mut(PADDING)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = include_str!("../fixtures/encryption.json");

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length: {s:?}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digits"))
            .collect()
    }

    fn key_hex(value: &serde_json::Value, name: &str) -> [u8; 32] {
        let bytes = unhex(value[name].as_str().expect("key string"));
        bytes.try_into().expect("32-byte key")
    }

    fn options(json: &serde_json::Value) -> EncryptionOptions {
        EncryptionOptions {
            block: json["block"].as_bool().expect("block flag"),
            compat: json["compat"].as_bool().expect("compat flag"),
        }
    }

    fn block_of(plaintext: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; PADDING];
        block.extend_from_slice(plaintext);
        block
    }

    #[test]
    fn matches_js_vectors() {
        let json: serde_json::Value = serde_json::from_str(FIXTURES).expect("fixture json");
        assert_eq!(json["padding"].as_u64(), Some(PADDING as u64));
        let cases = json["cases"].as_array().expect("cases");
        assert!(!cases.is_empty());

        let mut checked = 0;
        for case in cases {
            let opts = options(&case["options"]);
            let encryption_key = key_hex(case, "encryptionKey");
            let hypercore_key = key_hex(case, "hypercoreKey");
            let enc = BlockEncryption::new(&encryption_key, &hypercore_key, opts);
            let context = format!("block {} compat {}", opts.block, opts.compat);

            assert_eq!(
                enc.block_key(),
                &key_hex(case, "blockKey"),
                "block key {context}"
            );
            assert_eq!(
                enc.blinding_key(),
                &key_hex(case, "blindingKey"),
                "blinding key"
            );
            if opts.block {
                assert_eq!(enc.block_key(), &encryption_key);
            } else if opts.compat {
                assert_eq!(
                    enc.block_key(),
                    &crypto::keyed_hash(&hypercore_key, &[&encryption_key])
                );
            } else {
                assert_eq!(
                    enc.block_key(),
                    &BlockEncryption::block_encryption_key(&hypercore_key, &encryption_key)
                );
            }

            for vector in case["vectors"].as_array().expect("vectors") {
                let index = vector["index"].as_u64().expect("index");
                let fork = vector["fork"].as_u64().expect("fork");
                let plaintext = unhex(vector["plaintext"].as_str().expect("plaintext"));
                let ciphertext = unhex(vector["ciphertext"].as_str().expect("ciphertext"));
                let context = format!("index {index} fork {fork} len {}", plaintext.len());

                assert_eq!(
                    plaintext.len(),
                    vector["length"].as_u64().expect("length") as usize
                );
                assert_eq!(ciphertext.len(), plaintext.len() + PADDING, "{context}");

                let mut block = block_of(&plaintext);
                enc.encrypt(index, &mut block, fork);
                assert_eq!(block, ciphertext, "encrypt {context}");

                enc.decrypt(index, &mut block);
                assert_eq!(
                    &block[..PADDING],
                    &ciphertext[..PADDING],
                    "padding {context}"
                );
                assert_eq!(&block[PADDING..], &plaintext[..], "decrypt {context}");

                enc.encrypt(index, &mut block, fork);
                assert_eq!(block, ciphertext, "re-encrypt {context}");
                checked += 1;
            }
        }
        assert!(checked >= 100, "checked {checked} vectors");
    }

    #[test]
    fn decrypt_rejects_the_wrong_index() {
        let enc = BlockEncryption::new(&[1; 32], &[2; 32], EncryptionOptions::default());
        let plaintext = b"hypercore";
        let mut block = block_of(plaintext);
        enc.encrypt(7, &mut block, 0);

        enc.decrypt(8, &mut block);
        assert_ne!(&block[PADDING..], plaintext);
    }

    #[test]
    fn fork_travels_in_the_padding() {
        let enc = BlockEncryption::new(&[3; 32], &[4; 32], EncryptionOptions::default());
        let plaintext = b"reorged";
        let mut fork3 = block_of(plaintext);
        let mut fork4 = block_of(plaintext);
        enc.encrypt(1, &mut fork3, 3);
        enc.encrypt(1, &mut fork4, 4);
        assert_ne!(fork3, fork4, "fork changes the ciphertext");

        enc.decrypt(1, &mut fork4);
        assert_eq!(&fork4[PADDING..], plaintext);
        assert_ne!(
            &fork4[PADDING..],
            &fork3[PADDING..],
            "decrypting needs the stored fork"
        );
    }

    #[test]
    fn padding_depends_only_on_index_and_fork() {
        let enc = BlockEncryption::new(&[5; 32], &[6; 32], EncryptionOptions::default());
        let mut short = block_of(b"a");
        let mut long = block_of(b"a much longer block of plaintext");
        enc.encrypt(0, &mut short, 0);
        enc.encrypt(0, &mut long, 0);
        assert_eq!(short[..PADDING], long[..PADDING], "same index and fork");
        assert_eq!(enc.padding(), PADDING);

        enc.encrypt(1, &mut short, 0);
        assert_ne!(
            short[..PADDING],
            long[..PADDING],
            "index changes the padding"
        );
    }

    #[test]
    fn block_key_option_ignores_the_hypercore_key() {
        let opts = EncryptionOptions {
            block: true,
            compat: false,
        };
        let a = BlockEncryption::new(&[9; 32], &[0; 32], opts);
        let b = BlockEncryption::new(&[9; 32], &[7; 32], opts);
        assert_eq!(a.block_key(), b.block_key());
        assert_eq!(a.block_key(), &[9; 32]);

        let compat = EncryptionOptions {
            block: false,
            compat: true,
        };
        let derived = BlockEncryption::block_encryption_key(&[7; 32], &[9; 32]);
        assert_ne!(
            BlockEncryption::new(&[9; 32], &[7; 32], compat).block_key(),
            &derived
        );
    }

    #[test]
    #[should_panic(expected = "shorter than the padding prefix")]
    fn block_shorter_than_padding_is_rejected() {
        let enc = BlockEncryption::new(&[1; 32], &[2; 32], EncryptionOptions::default());
        let mut block = [0u8; PADDING - 1];
        enc.encrypt(0, &mut block, 0);
    }
}
