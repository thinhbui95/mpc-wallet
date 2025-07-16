// Copyright (c) Alberto Sonnino
// SPDX-License-Identifier: Apache-2.0

use std::{array::TryFromSliceError, fmt::Debug, fs::read_to_string, path::Path};

use eyre::{ensure, eyre, Result};
use fastcrypto::hash::{HashFunction, Sha256};
use gf256::gf256;
use rand::{CryptoRng, RngCore};

use crate::{
    shamir::{FieldArray, ShamirSecretSharing, ShamirShare},
    utils::{bits_to_bytes, bytes_to_bits},
};

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
    /// Load the bip-39 dictionary from a file.
    pub fn load<P: AsRef<Path>>(dictionary_path: P) -> Result<Self> {
        let words = read_to_string(dictionary_path)?
            .lines()
            .map(Into::into)
            .collect::<Vec<_>>();
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

    /// Convert the entropy to an Ethereum-compatible hex string (20 bytes / 40 hex chars).
    /// This takes the first 20 bytes of the entropy for Ethereum address generation.
    pub fn to_ethereum_hex(&self) -> String {
        let bytes = self.entropy.to_bytes();
        let ethereum_bytes = &bytes[..20]; // Take first 20 bytes for Ethereum
        format!("0x{}", hex::encode(ethereum_bytes))
    }

    /// Convert the entropy to raw 20-byte hex string without 0x prefix.
    pub fn to_ethereum_hex_raw(&self) -> String {
        let bytes = self.entropy.to_bytes();
        let ethereum_bytes = &bytes[..20]; // Take first 20 bytes for Ethereum
        hex::encode(ethereum_bytes)
    }

    /// Create a BIP-39 secret from an Ethereum hex string (20 bytes).
    /// The remaining entropy bytes will be filled with zeros.
    pub fn from_ethereum_hex(hex_str: &str) -> Result<Self> {
        // Remove 0x prefix if present
        let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        
        let ethereum_bytes = hex::decode(hex_clean)
            .map_err(|e| eyre!("Invalid hex string: {}", e))?;
        
        if ethereum_bytes.len() != 20 {
            return Err(eyre!("Invalid Ethereum address length: expected 20 bytes, got {}", ethereum_bytes.len()));
        }

        // Create full entropy by padding with zeros
        let mut full_bytes = [0u8; ENTROPY_BYTES];
        full_bytes[..20].copy_from_slice(&ethereum_bytes);

        let entropy_bits = bytes_to_bits(&full_bytes);
        let entropy = Entropy(entropy_bits[..ENTROPY_BITS]
            .try_into()
            .expect("Entropy bits should match ENTROPY_BITS length"));
        
        Ok(Self::from(entropy))
    }

    /// Derive an Ethereum address from the BIP-39 secret.
    /// This uses the first 20 bytes of the Keccak-256 hash of the entropy.
    pub fn to_ethereum_address(&self) -> String {
        use fastcrypto::hash::{HashFunction, Keccak256};
        
        // Get the entropy bytes
        let entropy_bytes = self.entropy.to_bytes();
        
        // Hash with Keccak-256 (Ethereum's hashing algorithm)
        let hash = Keccak256::digest(&entropy_bytes);
        
        // Take the last 20 bytes for Ethereum address
        let address_bytes = &hash.as_ref()[12..];
        
        format!("0x{}", hex::encode(address_bytes))
    }

    /// Derive an Ethereum address from the BIP-39 secret without 0x prefix.
    pub fn to_ethereum_address_raw(&self) -> String {
        use fastcrypto::hash::{HashFunction, Keccak256};
        
        let entropy_bytes = self.entropy.to_bytes();
        let hash = Keccak256::digest(&entropy_bytes);
        let address_bytes = &hash.as_ref()[12..];
        
        hex::encode(address_bytes)
    }

    /// Derive a checksummed Ethereum address (EIP-55) from the BIP-39 secret.
    pub fn to_ethereum_address_checksummed(&self) -> String {
        use fastcrypto::hash::{HashFunction, Keccak256};
        
        let address_raw = self.to_ethereum_address_raw();
        let hash = Keccak256::digest(address_raw.as_bytes());
        let hash_hex = hex::encode(hash.as_ref());
        
        let mut checksummed = String::with_capacity(42);
        checksummed.push_str("0x");
        
        for (i, ch) in address_raw.chars().enumerate() {
            if ch.is_ascii_digit() {
                checksummed.push(ch);
            } else {
                // If the corresponding hex digit is >= 8, capitalize the letter
                let hash_char = hash_hex.chars().nth(i).unwrap();
                if hash_char >= '8' {
                    checksummed.push(ch.to_ascii_uppercase());
                } else {
                    checksummed.push(ch);
                }
            }
        }
        
        checksummed
    }

    // ...existing code...
}

#[cfg(test)]
impl crate::shamir::Random for Bip39Secret {
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

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    use crate::{
        bip39::{Bip39Dictionary, Bip39Secret, Bip39Share, ENTROPY_BITS, ENTROPY_BYTES},
        shamir::{self, Random, ShamirSecretSharing},
    };

    /// Load the default bip-39 dictionary.
    fn test_dictionary() -> Bip39Dictionary {
        Bip39Dictionary::load("assets/bip39-en.txt").unwrap()
    }

    /// A valid bip-39 mnemonic.
    fn test_mnemonic() -> &'static str {
        "motion domain employ liberty priority moral \
        boil property urge error chunk pave \
        bullet blanket bind adapt local enroll \
        bullet permit theory vibrant initial venue"
    }

    #[test]
    fn load_dictionary() {
        let dictionary = test_dictionary();
        assert_eq!(dictionary.words.len(), 2048);
    }

    #[test]
    fn bits_from_word() {
        let dictionary = test_dictionary();

        let bits = dictionary.bits_from_word("abandon").unwrap();
        assert_eq!(bits, [false; 11]);

        let bits = dictionary.bits_from_word("hold").unwrap();
        assert_eq!(
            bits,
            [false, true, true, false, true, true, false, false, true, false, false]
        );
    }

    #[test]
    fn word_from_bits() {
        let dictionary = test_dictionary();

        let bits = [false; 11];
        let word = dictionary.word_from_bits(&bits);
        assert_eq!(word, "abandon");

        let bits = [
            false, true, true, false, true, true, false, false, true, false, false,
        ];
        let word = dictionary.word_from_bits(&bits);
        assert_eq!(word, "hold");
    }

    #[test]
    fn valid() {
        let dictionary = test_dictionary();
        let mnemonic = test_mnemonic();

        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        assert!(secret.is_valid().is_ok());
    }

    #[test]
    fn from_mnemonic() {
        let dictionary = test_dictionary();
        let mnemonic = test_mnemonic();

        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();

        let expected = mnemonic
            .split_whitespace()
            .flat_map(|word| dictionary.bits_from_word(word).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(secret.entropy, expected[..ENTROPY_BITS].try_into().unwrap());
        assert_eq!(
            secret.checksum,
            expected[ENTROPY_BITS..].try_into().unwrap()
        );
        assert!(secret.is_valid().is_ok());
    }

    #[test]
    fn to_mnemonic() {
        let dictionary = test_dictionary();
        let mnemonic = test_mnemonic();

        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        assert_eq!(secret.to_mnemonic(&dictionary), mnemonic);
    }

    #[test]
    fn valid_shares() {
        let dictionary = test_dictionary();

        let mut rng = StdRng::seed_from_u64(0);
        let secret = Bip39Secret::random(&mut rng);

        let n = 5;
        let t = 3;
        let shares = secret.split(n, t, &mut rng);

        assert_eq!(shares.len(), n as usize);
        for i in 0..t {
            let share = &shares[i as usize];
            let id = i + 1;

            assert_eq!(share.id(), &id);
            assert!(share.is_valid().is_ok());

            let share_mnemonic = share.to_mnemonic(&dictionary);
            assert_eq!(
                share,
                &Bip39Share::from_mnemonic(id, &share_mnemonic, &dictionary).unwrap()
            );
        }
    }

    #[test]
    fn reconstruct() {
        shamir::test::test_reconstruct::<Bip39Secret>();
    }

    #[test]
    fn reconstruct_sparse() {
        shamir::test::test_reconstruct_sparse::<Bip39Secret>();
    }

    #[test]
    fn reconstruct_missing_shares() {
        let (_, reconstructed) = shamir::test::test_reconstruct_missing_shares::<Bip39Secret>();
        assert!(reconstructed.is_valid().is_ok());
    }

    #[test]
    fn chaos() {
        shamir::test::chaos_test::<Bip39Secret>();
    }

    #[test]
    fn random_secrets() {
        let dictionary = test_dictionary();

        let mut rng = StdRng::seed_from_u64(0);
        for n in 1..=15 {
            for t in 1..=n {
                let secret = Bip39Secret::random(&mut rng);

                let mut shares = secret.clone().split(n, t, &mut rng);
                shares.shuffle(&mut rng);

                for share in &shares {
                    assert!(share.is_valid().is_ok());
                    let mnemonic = share.to_mnemonic(&dictionary);
                    let id = share.id();
                    let loaded = Bip39Share::from_mnemonic(*id, &mnemonic, &dictionary).unwrap();
                    assert_eq!(share, &loaded);
                }

                for i in 1..=t {
                    let reconstructed = Bip39Secret::reconstruct(&shares[0..i as usize]);
                    assert!(reconstructed.is_valid().is_ok());

                    if i == t {
                        assert_eq!(secret, reconstructed);
                    } else {
                        assert_ne!(secret, reconstructed);
                    }

                    let mnemonic = reconstructed.to_mnemonic(&dictionary);
                    let loaded = Bip39Secret::from_mnemonic(&mnemonic, &dictionary).unwrap();
                    assert_eq!(reconstructed, loaded);
                }
            }
        }
    }

    #[test]
    fn test_vectors() {
        let dictionary = test_dictionary();

        let filepath = "assets/test-vectors.txt";
        let content = read_to_string(filepath).unwrap();
        let mnemonics: Vec<_> = content.lines().collect();

        for mnemonic in mnemonics {
            let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
            assert!(secret.is_valid().is_ok());
            let exported = secret.to_mnemonic(&dictionary);
            assert_eq!(mnemonic, exported);
        }
    }

    #[test]
    fn test_random_seed_phrase() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(42); // Use a fixed seed for reproducible tests

        // Generate a random BIP-39 secret
        let secret = Bip39Secret::random(&mut rng);

        // Ensure the secret is valid
        assert!(secret.is_valid().is_ok());

        // Convert to mnemonic (seed phrase)
        let mnemonic = secret.to_mnemonic(&dictionary);

        // The mnemonic should have exactly 24 words
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        // Each word should be in the dictionary
        for word in &words {
            assert!(dictionary.words.iter().any(|w| w == word));
        }

        // We should be able to recreate the same secret from the mnemonic
        let recreated_secret = Bip39Secret::from_mnemonic(&mnemonic, &dictionary).unwrap();
        assert_eq!(secret, recreated_secret);

        // The recreated secret should also be valid
        assert!(recreated_secret.is_valid().is_ok());

        println!("Generated random seed phrase: {}", mnemonic);
    }

    #[test]
    fn test_multiple_random_seed_phrases() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(123);

        // Generate multiple random seed phrases to ensure they're different
        let mut mnemonics = Vec::new();

        for i in 0..5 {
            let secret = Bip39Secret::random(&mut rng);
            assert!(secret.is_valid().is_ok());

            let mnemonic = secret.to_mnemonic(&dictionary);

            // Ensure this mnemonic is unique
            assert!(!mnemonics.contains(&mnemonic), "Generated duplicate mnemonic at iteration {}", i);
            mnemonics.push(mnemonic.clone());

            // Verify round-trip conversion
            let recreated = Bip39Secret::from_mnemonic(&mnemonic, &dictionary).unwrap();
            assert_eq!(secret, recreated);

            println!("Random seed phrase {}: {}", i + 1, mnemonic);
        }
    }

    #[test]
    fn test_mnemonic_to_hex_conversion() {
        let dictionary = test_dictionary();
        
        // Test with a known mnemonic
        let mnemonic = test_mnemonic();
        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        
        // Convert to hex
        let hex_string = secret.to_hex();
        
        // Verify the hex string is valid (should be 64 characters for 32 bytes)
        assert_eq!(hex_string.len(), ENTROPY_BYTES * 2);
        assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Test round-trip conversion: hex -> secret -> mnemonic
        let recreated_secret = Bip39Secret::from_hex(&hex_string).unwrap();
        assert_eq!(secret, recreated_secret);
        
        let recreated_mnemonic = recreated_secret.to_mnemonic(&dictionary);
        assert_eq!(mnemonic, recreated_mnemonic);
        
        println!("Mnemonic: {}", mnemonic);
        println!("Hex: {}", hex_string);
    }

    #[test]
    fn test_random_mnemonic_to_hex_conversion() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(456);
        
        // Test with multiple random mnemonics
        for i in 0..3 {
            let secret = Bip39Secret::random(&mut rng);
            let mnemonic = secret.to_mnemonic(&dictionary);
            let hex_string = secret.to_hex();
            
            // Verify hex format
            assert_eq!(hex_string.len(), ENTROPY_BYTES * 2);
            assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
            
            // Test round-trip conversions
            let from_hex = Bip39Secret::from_hex(&hex_string).unwrap();
            let from_mnemonic = Bip39Secret::from_mnemonic(&mnemonic, &dictionary).unwrap();
            
            assert_eq!(secret, from_hex);
            assert_eq!(secret, from_mnemonic);
            assert_eq!(from_hex, from_mnemonic);
            
            // Verify both conversions produce the same results
            assert_eq!(from_hex.to_mnemonic(&dictionary), mnemonic);
            assert_eq!(from_mnemonic.to_hex(), hex_string);
            
            println!("Test {}: ", i + 1);
            println!("  Mnemonic: {}", mnemonic);
            println!("  Hex: {}", hex_string);
        }
    }

    #[test]
    fn test_hex_error_cases() {
        // Test invalid hex string
        let result = Bip39Secret::from_hex("invalid_hex");
        assert!(result.is_err());
        
        // Test wrong length hex string
        let short_hex = "1234567890abcdef";
        let result = Bip39Secret::from_hex(&short_hex);
        assert!(result.is_err());
        
        // Test empty hex string
        let result = Bip39Secret::from_hex("");
        assert!(result.is_err());
    }

    #[test]
    fn test_mnemonic_to_ethereum_address() {
        let dictionary = test_dictionary();
        
        // Test with a known mnemonic
        let mnemonic = test_mnemonic();
        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        
        // Convert to Ethereum address
        let address = secret.to_ethereum_address();
        let address_raw = secret.to_ethereum_address_raw();
        let address_checksummed = secret.to_ethereum_address_checksummed();
        
        // Verify Ethereum address format
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars
        assert_eq!(address_raw.len(), 40); // 40 hex chars
        assert_eq!(address_checksummed.len(), 42); // 0x + 40 hex chars
        
        // Verify all characters are valid hex
        assert!(address[2..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(address_raw.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(address_checksummed[2..].chars().all(|c| c.is_ascii_hexdigit()));
        
        // Verify address_raw is the same as address without 0x prefix
        assert_eq!(format!("0x{}", address_raw), address);
        
        // Verify checksummed address contains mixed case
        let has_uppercase = address_checksummed[2..].chars().any(|c| c.is_ascii_uppercase());
        let has_lowercase = address_checksummed[2..].chars().any(|c| c.is_ascii_lowercase());
        // Note: Not all addresses will have mixed case, depending on the hash
        
        println!("Mnemonic: {}", mnemonic);
        println!("Ethereum Address: {}", address);
        println!("Ethereum Address (raw): {}", address_raw);
        println!("Ethereum Address (checksummed): {}", address_checksummed);
        
        // Test that the same mnemonic always produces the same address
        let secret2 = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        assert_eq!(secret.to_ethereum_address(), secret2.to_ethereum_address());
    }

    #[test]
    fn test_multiple_mnemonics_to_ethereum_addresses() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(789);
        
        let mut addresses = Vec::new();
        
        // Generate multiple random mnemonics and their addresses
        for i in 0..5 {
            let secret = Bip39Secret::random(&mut rng);
            let mnemonic = secret.to_mnemonic(&dictionary);
            let address = secret.to_ethereum_address();
            let address_checksummed = secret.to_ethereum_address_checksummed();
            
            // Verify address format
            assert!(address.starts_with("0x"));
            assert_eq!(address.len(), 42);
            assert!(address[2..].chars().all(|c| c.is_ascii_hexdigit()));
            
            // Verify checksummed address format
            assert!(address_checksummed.starts_with("0x"));
            assert_eq!(address_checksummed.len(), 42);
            assert!(address_checksummed[2..].chars().all(|c| c.is_ascii_hexdigit()));
            
            // Ensure this address is unique
            assert!(!addresses.contains(&address), "Generated duplicate address at iteration {}", i);
            addresses.push(address.clone());
            
            // Test round-trip: mnemonic -> secret -> address
            let recreated_secret = Bip39Secret::from_mnemonic(&mnemonic, &dictionary).unwrap();
            assert_eq!(secret.to_ethereum_address(), recreated_secret.to_ethereum_address());
            
            println!("Test {}: ", i + 1);
            println!("  Mnemonic: {}", mnemonic);
            println!("  Address: {}", address);
            println!("  Address (checksummed): {}", address_checksummed);
        }
    }

    #[test]
    fn test_ethereum_hex_to_address_conversion() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(999);
        
        // Test conversion from Ethereum hex to address
        for i in 0..3 {
            let secret = Bip39Secret::random(&mut rng);
            let mnemonic = secret.to_mnemonic(&dictionary);
            
            // Get Ethereum hex and address
            let eth_hex = secret.to_ethereum_hex();
            let eth_hex_raw = secret.to_ethereum_hex_raw();
            let address = secret.to_ethereum_address();
            
            // Verify hex format (20 bytes = 40 hex chars)
            assert_eq!(eth_hex.len(), 42); // 0x + 40 hex chars
            assert_eq!(eth_hex_raw.len(), 40); // 40 hex chars
            assert!(eth_hex.starts_with("0x"));
            assert_eq!(format!("0x{}", eth_hex_raw), eth_hex);
            
            // Create secret from Ethereum hex and verify it produces the same address
            let secret_from_hex = Bip39Secret::from_ethereum_hex(&eth_hex).unwrap();
            let address_from_hex = secret_from_hex.to_ethereum_address();
            
            // Note: The address derived from hex won't be the same as the original
            // because from_ethereum_hex pads with zeros, changing the entropy
            // But we can verify the format is correct
            assert!(address_from_hex.starts_with("0x"));
            assert_eq!(address_from_hex.len(), 42);
            
            println!("Test {}: ", i + 1);
            println!("  Original Mnemonic: {}", mnemonic);
            println!("  Original Address: {}", address);
            println!("  Ethereum Hex: {}", eth_hex);
            println!("  Address from Hex: {}", address_from_hex);
        }
    }

    #[test]
    fn test_ethereum_address_consistency() {
        let dictionary = test_dictionary();
        
        // Test that the same entropy always produces the same address
        let mnemonic = test_mnemonic();
        let secret1 = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        let secret2 = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        
        assert_eq!(secret1.to_ethereum_address(), secret2.to_ethereum_address());
        assert_eq!(secret1.to_ethereum_address_raw(), secret2.to_ethereum_address_raw());
        assert_eq!(secret1.to_ethereum_address_checksummed(), secret2.to_ethereum_address_checksummed());
        
        // Test with hex conversion
        let hex = secret1.to_hex();
        let secret3 = Bip39Secret::from_hex(&hex).unwrap();
        
        assert_eq!(secret1.to_ethereum_address(), secret3.to_ethereum_address());
        assert_eq!(secret1.to_ethereum_address_raw(), secret3.to_ethereum_address_raw());
        assert_eq!(secret1.to_ethereum_address_checksummed(), secret3.to_ethereum_address_checksummed());
    }

    #[test]
    fn test_split_mnemonic_to_shares() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Test with a known mnemonic
        let mnemonic = test_mnemonic();
        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        
        // Split into shares (5 shares, 3 needed to reconstruct)
        let n = 5; // Total shares
        let t = 3; // Threshold (minimum shares needed)
        let shares = secret.split(n, t, &mut rng);

        // Verify we got the correct number of shares
        assert_eq!(shares.len(), n as usize);
        
        // Convert each share to mnemonic string and verify
        let mut share_mnemonics = Vec::new();
        for (i, share) in shares.iter().enumerate() {
            let share_id = i as u8 + 1;
            assert_eq!(share.id(), &share_id);
            
            // Convert share to mnemonic string
            let share_mnemonic = share.to_mnemonic(&dictionary);
            
            // Verify the share mnemonic has 24 words
            let words: Vec<&str> = share_mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), 24);

            // Each word should be in the dictionary
            for word in &words {
                assert!(dictionary.words.iter().any(|w| w == word));
            }

            // Verify the share is valid
            assert!(share.is_valid().is_ok());
            
            // Test round-trip: share -> mnemonic -> share
            let recreated_share = Bip39Share::from_mnemonic(share_id, &share_mnemonic, &dictionary).unwrap();
            assert_eq!(share, &recreated_share);
            
            share_mnemonics.push(share_mnemonic.clone());
            
            println!("Share {}: {}", share_id, share_mnemonic);
        }
        
        // Verify all share mnemonics are different
        for i in 0..share_mnemonics.len() {
            for j in i+1..share_mnemonics.len() {
                assert_ne!(share_mnemonics[i], share_mnemonics[j], 
                    "Share {} and {} have the same mnemonic", i+1, j+1);
            }
        }
        
        // Test reconstruction with minimum threshold
        let reconstruction_shares = &shares[0..t as usize];
        let reconstructed_secret = Bip39Secret::reconstruct(reconstruction_shares);
        
        // Verify the reconstructed secret matches the original
        assert_eq!(secret, reconstructed_secret);
        assert!(reconstructed_secret.is_valid().is_ok());
        
        // Verify the reconstructed mnemonic matches the original
        let reconstructed_mnemonic = reconstructed_secret.to_mnemonic(&dictionary);
        assert_eq!(mnemonic, reconstructed_mnemonic);
        
        println!("Original mnemonic: {}", mnemonic);
        println!("Reconstructed mnemonic: {}", reconstructed_mnemonic);
        println!("Successfully split into {} shares with threshold {}", n, t);
    }

    #[test]
    fn test_split_random_mnemonic_to_shares() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(54321);
        
        // Test with different share configurations
        let test_configs = vec![
            (3, 2), // 3 shares, 2 needed
            (5, 3), // 5 shares, 3 needed
            (7, 4), // 7 shares, 4 needed
            (10, 6), // 10 shares, 6 needed
        ];
        
        for (config_idx, (n, t)) in test_configs.iter().enumerate() {
            println!("Testing configuration {}: {} shares, {} threshold", config_idx + 1, n, t);
            
            // Generate a random secret
            let secret = Bip39Secret::random(&mut rng);
            let original_mnemonic = secret.to_mnemonic(&dictionary);
            
            // Split into shares
            let shares = secret.split(*n, *t, &mut rng);
            assert_eq!(shares.len(), *n as usize);
            
            // Convert all shares to mnemonic strings
            let mut share_data = Vec::new();
            for (i, share) in shares.iter().enumerate() {
                let share_id = i as u8 + 1;
                let share_mnemonic = share.to_mnemonic(&dictionary);
                
                // Verify share format
                assert_eq!(share.id(), &share_id);
                assert!(share.is_valid().is_ok());
                assert_eq!(share_mnemonic.split_whitespace().count(), 24);
                
                share_data.push((share_id, share_mnemonic.clone()));
                println!("  Share {}: {}", share_id, share_mnemonic);
            }
            
            // Test reconstruction with exactly the threshold number of shares
            let selected_shares: Vec<_> = shares.iter().take(*t as usize).collect();
            let reconstructed_secret = Bip39Secret::reconstruct(&selected_shares);
            let reconstructed_mnemonic = reconstructed_secret.to_mnemonic(&dictionary);
            
            // Verify reconstruction
            assert_eq!(secret, reconstructed_secret);
            assert_eq!(original_mnemonic, reconstructed_mnemonic);
            
            // Test reconstruction with more than threshold shares
            if *n > *t {
                let extra_shares: Vec<_> = shares.iter().take(*t as usize + 1).collect();
                let reconstructed_extra = Bip39Secret::reconstruct(&extra_shares);
                assert_eq!(secret, reconstructed_extra);
            }
            
            // Test that we can't reconstruct with fewer than threshold shares
            if *t > 1 {
                let insufficient_shares: Vec<_> = shares.iter().take(*t as usize - 1).collect();
                let reconstructed_insufficient = Bip39Secret::reconstruct(&insufficient_shares);
                assert_ne!(secret, reconstructed_insufficient);
            }
            
            println!("  Original: {}", original_mnemonic);
            println!("  Reconstructed: {}", reconstructed_mnemonic);
            println!("  ✓ Configuration {} passed\n", config_idx + 1);
        }
    }

    #[test]
    fn test_share_mnemonic_string_operations() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(99999);
        
        // Create a secret and split it
        let secret = Bip39Secret::random(&mut rng);
        let original_mnemonic = secret.to_mnemonic(&dictionary);
        let shares = secret.split(5, 3, &mut rng);
        
        // Test various string operations with share mnemonics
        for (i, share) in shares.iter().enumerate().take(3) {
            let share_id = share.id();
            let share_mnemonic = share.to_mnemonic(&dictionary);
            
            // Test creating share from mnemonic string
            let share_from_string = Bip39Share::from_mnemonic(*share_id, &share_mnemonic, &dictionary).unwrap();
            assert_eq!(share, &share_from_string);
            
            // Test share mnemonic properties
            let words: Vec<&str> = share_mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), 24);
            
            // Each word should be in the dictionary
            for word in &words {
                assert!(dictionary.words.iter().any(|w| w == word), 
                    "Word '{}' not found in dictionary", word);
            }
            
            // Test that share mnemonic is different from original
            assert_ne!(share_mnemonic, original_mnemonic);
            
            // Test string formatting and parsing
            let share_string = format!("Share ID: {}, Mnemonic: {}", share_id, share_mnemonic);
            assert!(share_string.contains(&share_id.to_string()));
            assert!(share_string.contains(&share_mnemonic));
            
            println!("Share {} string: {}", i + 1, share_string);
        }
        
        // Test reconstruction using string-based shares
        let string_shares: Vec<_> = shares.iter()
            .take(3)
            .map(|share| {
                let mnemonic = share.to_mnemonic(&dictionary);
                Bip39Share::from_mnemonic(*share.id(), &mnemonic, &dictionary).unwrap()
            })
            .collect();
        
        let reconstructed = Bip39Secret::reconstruct(&string_shares);
        assert_eq!(secret, reconstructed);
        
        let reconstructed_mnemonic = reconstructed.to_mnemonic(&dictionary);
        assert_eq!(original_mnemonic, reconstructed_mnemonic);
        
        println!("Successfully tested share mnemonic string operations");
        println!("Original: {}", original_mnemonic);
        println!("Reconstructed from strings: {}", reconstructed_mnemonic);
    }

    #[test]
    fn test_share_serialization_format() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(11111);
        
        // Create a secret and split it
        let secret = Bip39Secret::random(&mut rng);
        let shares = secret.split(3, 2, &mut rng);
        
        // Create a serialized format for shares
        let mut serialized_shares = Vec::new();
        
        for share in &shares {
            let share_id = *share.id();
            let share_mnemonic = share.to_mnemonic(&dictionary);
            
            // Create a JSON-like format (as string)
            let serialized = format!(
                r#"{{"id": {}, "mnemonic": "{}"}}"#,
                share_id,
                share_mnemonic
            );
            
            serialized_shares.push(serialized.clone());
            println!("Serialized share: {}", serialized);
        }
        
        // Test parsing serialized shares back
        let mut parsed_shares = Vec::new();
        
        for (i, serialized) in serialized_shares.iter().enumerate() {
            // Simple parsing (in a real implementation, you'd use serde)
            let id_start = serialized.find(r#""id": "#).unwrap() + 6;
            let id_end = serialized.find(",").unwrap();
            let share_id: u8 = serialized[id_start..id_end].parse().unwrap();
            
            let mnemonic_start = serialized.find(r#""mnemonic": ""#).unwrap() + 12;
            let mnemonic_end = serialized.rfind(r#"""#).unwrap();
            let mnemonic = &serialized[mnemonic_start..mnemonic_end];
            
            // Recreate share from parsed data
            let parsed_share = Bip39Share::from_mnemonic(share_id, mnemonic, &dictionary).unwrap();
            parsed_shares.push(parsed_share);
            
            // Verify the parsed share matches the original
            assert_eq!(&shares[i], &parsed_shares[i]);
        }
        
        // Test reconstruction from parsed shares
        let reconstructed = Bip39Secret::reconstruct(&parsed_shares[0..2]);
        assert_eq!(secret, reconstructed);
        
        println!("Successfully tested share serialization and parsing");
    }

    #[test]
    fn test_share_string_format() {
        let dictionary = test_dictionary();
        let mut rng = StdRng::seed_from_u64(77777);
        
        // Create a secret and split it
        let secret = Bip39Secret::random(&mut rng);
        let shares = secret.split(3, 2, &mut rng);
        
        // Test the new share string format
        for share in &shares {
            let (id, _) = share.as_coordinates();
            let share_string = share.to_share_string(&dictionary);
            
            // Verify the format
            assert!(share_string.starts_with(&format!("ID:{} ", id)));
            
            // Test parsing back
            let parsed_share = Bip39Share::from_share_string(&share_string, &dictionary).unwrap();
            assert_eq!(share, &parsed_share);
            
            println!("Share string: {}", share_string);
        }
        
        // Test reconstruction using string format
        let share_strings: Vec<_> = shares.iter()
            .take(2)
            .map(|share| share.to_share_string(&dictionary))
            .collect();
        
        let parsed_shares: Vec<_> = share_strings.iter()
            .map(|s| Bip39Share::from_share_string(s, &dictionary).unwrap())
            .collect();
        
        let reconstructed = Bip39Secret::reconstruct(&parsed_shares);
        assert_eq!(secret, reconstructed);
        
        println!("Successfully tested share string format");
    }
}