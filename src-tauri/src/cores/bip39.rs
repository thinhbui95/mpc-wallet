// Copyright (c) Alberto Sonnino
// SPDX-License-Identifier: Apache-2.0

use std::{array::TryFromSliceError, fmt::Debug, fs::read_to_string, path::Path};

use eyre::{ensure, eyre, Result};
use fastcrypto::hash::{HashFunction, Sha256};
use gf256::gf256;
use rand::{CryptoRng, RngCore};

use crate::cores::shamir::{FieldArray, ShamirSecretSharing, ShamirShare};
use crate::cores::utils::{bits_to_bytes, bytes_to_bits};


/// Parameters of the bip-39 specification (24 words variant).
const DICTIONARY_INDICES_BITS: usize = 11;
const MNEMONIC_WORDS: usize = 24;
const DICTIONARY_WORDS: usize = 2 << (DICTIONARY_INDICES_BITS - 1);
const CHECKSUM_BITS: usize = (MNEMONIC_WORDS * DICTIONARY_INDICES_BITS) / 33;
const ENTROPY_BITS: usize = CHECKSUM_BITS * 32;
const ENTROPY_BYTES: usize = ENTROPY_BITS / 8;

/// The bip-39 dictionary.
pub struct Bip39Dictionary {
    words: [String; DICTIONARY_WORDS],
}

impl Bip39Dictionary {
    /// Load the English BIP-39 wordlist embedded in the binary.
    pub fn load_embedded() -> Result<Self> {
        Self::from_text(include_str!("../../assets/bip39-en.txt"))
    }

    /// Load the bip-39 dictionary from a file.
    pub fn load<P: AsRef<Path>>(dictionary_path: P) -> Result<Self> {
        Self::from_text(&read_to_string(dictionary_path)?)
    }

    fn from_text(text: &str) -> Result<Self> {
        let words = text.lines().map(Into::into).collect::<Vec<_>>();
        let length = words.len();

        Ok(Self {
            words: words.try_into().map_err(|_| {
                eyre!("Invalid BIP-39 dictionary length {length} != {DICTIONARY_WORDS}")
            })?,
        })
    }

    /// Get the index of a word in the dictionary (as bits).
    pub fn bits_from_word(&self, word: &str) -> Result<[bool; DICTIONARY_INDICES_BITS]> {
        let index = self
            .words
            .iter()
            .position(|w| w == word)
            .ok_or(eyre!("Invalid BIP-39 word '{word}' in mnemonic"))?;
        let bits = bytes_to_bits(&index.to_be_bytes());
        Ok(bits[bits.len() - DICTIONARY_INDICES_BITS..]
            .try_into()
            .expect("Slice size should match the dictionary index bit length"))
    }

    /// Get the word at a given index in the dictionary.
    pub fn word_from_bits(&self, bits: &[bool; DICTIONARY_INDICES_BITS]) -> String {
        let mut extended = bytes_to_bits(&usize::to_be_bytes(0));
        let length = extended.len();
        extended[length - DICTIONARY_INDICES_BITS..].copy_from_slice(bits);
        let bytes = bits_to_bytes(&extended)
            .try_into()
            .expect("Slice size should match the dictionary index byte length");
        let index = usize::from_be_bytes(bytes);
        self.words[index].clone()
    }
}

/// The entropy of a bip-39 secret.
#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug, Clone))]
struct Entropy([bool; ENTROPY_BITS]);

impl Entropy {
    pub fn as_bits(&self) -> &[bool] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; ENTROPY_BYTES] {
        bits_to_bytes(&self.0).try_into().unwrap()
    }

    #[cfg(test)]
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        use rand::Rng;

        Self(std::array::from_fn(|_| rng.random()))
    }
}

impl TryFrom<&[bool]> for Entropy {
    type Error = TryFromSliceError;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl<T> From<FieldArray<T, ENTROPY_BYTES>> for Entropy
where
    u8: From<T>,
{
    fn from(value: FieldArray<T, ENTROPY_BYTES>) -> Self {
        let bytes = value.into_iter().map(u8::from).collect::<Vec<_>>();
        bytes_to_bits(&bytes).as_slice().try_into().unwrap()
    }
}

impl<T> From<&Entropy> for FieldArray<T, ENTROPY_BYTES>
where
    T: From<u8> + Debug,
{
    fn from(value: &Entropy) -> Self {
        value.to_bytes().map(T::from).into()
    }
}

/// The checksum of a bip-39 secret.
#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Clone, Debug))]
struct Checksum([bool; CHECKSUM_BITS]);

impl TryFrom<&[bool]> for Checksum {
    type Error = TryFromSliceError;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<&Entropy> for Checksum {
    fn from(entropy: &Entropy) -> Self {
        let digest = Sha256::digest(entropy.to_bytes());
        let bits = bytes_to_bits(digest.as_ref());
        let checksum = bits[..CHECKSUM_BITS]
            .try_into()
            .expect("Slice size should match the checksum bit length");
        Self(checksum)
    }
}

impl Checksum {
    pub fn as_bits(&self) -> &[bool] {
        &self.0
    }
}

/// A bip-39 secret.
#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug, Clone))]
pub struct Bip39Secret {
    /// The entropy of the secret.
    entropy: Entropy,
    /// The checksum of the secret.
    checksum: Checksum,
}

impl ShamirSecretSharing for Bip39Secret {
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<Bip39Share> {
        FieldArray::<gf256, ENTROPY_BYTES>::from(&self.entropy)
            .split(n, t, rng)
            .into_iter()
            .map(|share| {
                let (id, secret) = share.into_inner();
                let entropy = Entropy::from(secret);
                Bip39Share::new(id, Self::from(entropy))
            })
            .collect()
    }

    fn reconstruct<S: AsRef<Bip39Share>>(shares: &[S]) -> Self {
        let array_shares = shares
            .iter()
            .map(|share| {
                let (id, secret) = share.as_ref().as_coordinates();
                let array = FieldArray::from(&secret.entropy);
                ShamirShare::new(*id, array)
            })
            .collect::<Vec<_>>();

        let array = FieldArray::<gf256, ENTROPY_BYTES>::reconstruct(&array_shares);
        let entropy = Entropy::from(array);
        Self::from(entropy)
    }
}

impl Bip39Secret {
    /// Ensure the checksum of the secret is valid.
    pub fn is_valid(&self) -> Result<()> {
        let checksum = Checksum::from(&self.entropy);
        ensure!(self.checksum == checksum, "Invalid checksum");
        Ok(())
    }

    /// Create a new secret from a given mnemonic.
    pub fn from_mnemonic(mnemonic: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        let words = mnemonic.split_whitespace().collect::<Vec<_>>();
        let length = words.len();

        let bits = TryInto::<[&str; MNEMONIC_WORDS]>::try_into(words)
            .map_err(|_| eyre!("Invalid mnemonic length {length} != {MNEMONIC_WORDS}"))?
            .into_iter()
            .map(|word| dictionary.bits_from_word(word))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(Self {
            entropy: bits[..ENTROPY_BITS]
                .try_into()
                .expect("Valid mnemonic should be longer than the entropy bit length"),
            checksum: bits[ENTROPY_BITS..].try_into().expect(
                "Valid mnemonic should match the sum of the entropy and checksum bit length",
            ),
        })
    }

    /// Generate a mnemonic from the secret.
    pub fn to_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        self.entropy
            .as_bits()
            .iter()
            .cloned()
            .chain(self.checksum.as_bits().iter().cloned())
            .collect::<Vec<_>>()
            .chunks(DICTIONARY_INDICES_BITS)
            .map(|chunk| {
                let bits = chunk.try_into().expect(
                    "The secret bit length should be divisible by the dictionary index bit length",
                );
                dictionary.word_from_bits(bits)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Generate a random BIP-39 secret and return its mnemonic representation.
    /// This is useful for creating new wallet seed phrases.
    pub fn generate_random_mnemonic<R: CryptoRng + RngCore>(
        rng: &mut R,
        dictionary: &Bip39Dictionary,
    ) -> String {
        use rand::Rng;
        let entropy = Entropy(std::array::from_fn(|_| rng.random()));
        let secret = Self::from(entropy);
        secret.to_mnemonic(dictionary)
    }

    /// Convert the entropy of the BIP-39 secret to a hex string.
    /// This returns the raw entropy bytes as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.entropy.to_bytes())
    }

    /// Create a BIP-39 secret from a hex string.
    /// The hex string should represent the entropy bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| eyre!("Invalid hex string: {}", e))?;
        
        if bytes.len() != ENTROPY_BYTES {
            return Err(eyre!("Invalid entropy length: expected {} bytes, got {}", ENTROPY_BYTES, bytes.len()));
        }

        let entropy_bits = bytes_to_bits(&bytes);
        let entropy = Entropy(entropy_bits[..ENTROPY_BITS]
            .try_into()
            .expect("Entropy bits should match ENTROPY_BITS length"));
        
        Ok(Self::from(entropy))
    }

}

#[cfg(test)]
impl crate::cores::shamir::Random for Bip39Secret {
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self::from(Entropy::random(rng))
    }
}

impl From<Entropy> for Bip39Secret {
    fn from(entropy: Entropy) -> Self {
        let checksum = Checksum::from(&entropy);
        Self { entropy, checksum }
    }
}

pub type Bip39Share = ShamirShare<Bip39Secret>;

impl Bip39Share {
    /// Convert a share to a formatted string containing both ID and mnemonic.
    /// Format: "ID:{id} {mnemonic}"
    pub fn to_share_string(&self, dictionary: &Bip39Dictionary) -> String {
        let (id, _) = self.as_coordinates();
        format!("ID:{} {}", id, self.to_mnemonic(dictionary))
    }

    /// Create a share from a formatted share string.
    /// Expected format: "ID:{id} {mnemonic}"
    pub fn from_share_string(share_string: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        if !share_string.starts_with("ID:") {
            return Err(eyre!("Invalid share string format: must start with 'ID:'"));
        }
        
        let parts: Vec<&str> = share_string.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err(eyre!("Invalid share string format: missing mnemonic part"));
        }
        
        let id_part = parts[0];
        let mnemonic_part = parts[1];
        
        // Parse the ID
        let id_str = id_part.strip_prefix("ID:").unwrap();
        let id: u8 = id_str.parse()
            .map_err(|_| eyre!("Invalid share ID: '{}'", id_str))?;
        
        // Create share from mnemonic
        Self::from_mnemonic(id, mnemonic_part, dictionary)
    }

    pub fn is_valid(&self) -> Result<()> {
        self.secret().is_valid()
    }

    pub fn from_mnemonic(id: u8, mnemonic: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        let secret = Bip39Secret::from_mnemonic(mnemonic, dictionary)?;
        Ok(Self::new(id, secret))
    }

    pub fn to_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        self.secret().to_mnemonic(dictionary)
    }
}

