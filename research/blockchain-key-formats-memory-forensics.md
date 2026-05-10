# Blockchain Private Key Formats & Memory Forensics Research

> Comprehensive reference for detecting and recovering cryptocurrency private keys,
> seed phrases, and wallet artifacts from memory dumps. Targeted at Rust-based
> memory forensics tooling implementation.

**Date:** 2026-03-30
**Status:** Research Complete

---

## Table of Contents

1. [Bitcoin Private Key Formats](#1-bitcoin-private-key-formats)
2. [Ethereum Private Key Formats](#2-ethereum-private-key-formats)
3. [BIP-39 Seed Phrases (Mnemonics)](#3-bip-39-seed-phrases-mnemonics)
4. [BIP-32/44 HD Wallet Derivation](#4-bip-3244-hd-wallet-derivation)
5. [Other Blockchain Private Key Formats](#5-other-blockchain-private-key-formats)
6. [Wallet Software Memory Patterns](#6-wallet-software-memory-patterns)
7. [Existing Tools for Crypto Key Recovery](#7-existing-tools-for-crypto-key-recovery)
8. [Detection Signatures & Implementation Guide](#8-detection-signatures--implementation-guide)
9. [Rust Implementation Strategy](#9-rust-implementation-strategy)

---

## 1. Bitcoin Private Key Formats

### 1.1 Raw 256-bit Private Key

The most fundamental form: a 32-byte (256-bit) unsigned big-endian integer.

**Byte Layout:**
```
[32 bytes] - Raw private key (big-endian)
```

**Validation Rules:**
- Must be in range [1, n-1] where n is the secp256k1 curve order
- n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
- Value of 0x00 (all zeros) is invalid
- Value >= n is invalid
- Effective key space: ~2^256 values

**Hex Pattern:**
```
[0-9a-fA-F]{64}  (64 hex characters = 32 bytes)
```

**False Positive Considerations:**
- Raw 32-byte hex strings are extremely common in memory (SHA-256 hashes, random data, etc.)
- Cannot reliably detect raw private keys without contextual clues (adjacent public key, wallet structures)
- Hex representation `[0-9a-f]{64}` matches any 32-byte hex string; overwhelmingly noisy
- Only viable when found adjacent to known wallet structures or preceded by known prefixes

**secp256k1 Curve Constants (for validation):**
```
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

### 1.2 WIF (Wallet Import Format)

The standard human-readable format for Bitcoin private keys. Uses Base58Check encoding.

**Byte Layout (Uncompressed):**
```
Offset  Size    Field
0       1       Version byte: 0x80 (mainnet) or 0xEF (testnet)
1       32      Raw private key (big-endian)
33      4       Checksum: first 4 bytes of SHA256(SHA256(version + key))
Total: 37 bytes -> Base58 encoded to 51 characters starting with '5'
```

**Byte Layout (Compressed):**
```
Offset  Size    Field
0       1       Version byte: 0x80 (mainnet) or 0xEF (testnet)
1       32      Raw private key (big-endian)
33      1       Compression flag: 0x01
34      4       Checksum: first 4 bytes of SHA256(SHA256(version + key + flag))
Total: 38 bytes -> Base58 encoded to 52 characters starting with 'K' or 'L'
```

**Base58 Alphabet:**
```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```
Note: Excludes 0 (zero), O (capital o), l (lowercase L), I (capital i).

**Detection Patterns:**

| Type | Prefix | Length | Regex |
|------|--------|--------|-------|
| WIF Uncompressed (mainnet) | `5` | 51 chars | `5[HJK][1-9A-HJ-NP-Za-km-z]{49}` |
| WIF Compressed (mainnet) | `K` or `L` | 52 chars | `[KL][1-9A-HJ-NP-Za-km-z]{51}` |
| WIF Uncompressed (testnet) | `9` | 51 chars | `9[1-9A-HJ-NP-Za-km-z]{50}` |
| WIF Compressed (testnet) | `c` | 52 chars | `c[1-9A-HJ-NP-Za-km-z]{51}` |

**Combined mainnet regex:**
```regex
[5KL][1-9A-HJ-NP-Za-km-z]{50,51}
```

**Validation (post-regex):**
1. Base58-decode the string
2. Split into payload (all bytes except last 4) and checksum (last 4 bytes)
3. Compute SHA256(SHA256(payload))
4. Compare first 4 bytes of hash to checksum
5. Verify version byte is 0x80 (mainnet) or 0xEF (testnet)
6. Verify private key value is in [1, n-1]

**False Positive Analysis:**
- Leading character constraint (`5`, `K`, `L`) significantly reduces false positives
- Base58Check checksum provides ~1 in 2^32 false positive rate after regex match
- Combined with length check, very low false positive rate
- **Recommended as primary detection target** due to high precision

### 1.3 Mini Private Key Format

Created for Casascius physical bitcoins. Compact format for QR codes.

**Format:**
- 30 characters (standard) or 22 characters (legacy Casascius Series 1)
- Always starts with uppercase 'S'
- Uses Base58 alphabet characters
- The actual 256-bit private key = SHA256(mini_key_string)

**Validation:**
1. Append `?` to the candidate string
2. Compute SHA256(candidate + "?")
3. First byte must be 0x00 for a valid mini key

**Regex:**
```regex
S[1-9A-HJ-NP-Za-km-z]{29}     # 30-char standard
S[1-9A-HJ-NP-Za-km-z]{21}     # 22-char legacy (Casascius Series 1)
```

**False Positive Considerations:**
- 'S' prefix plus Base58 characters is somewhat common
- SHA256 validation (first byte == 0x00) provides ~1/256 false positive rate
- Combined with length constraint: moderate false positive rate
- Less common in modern wallets; lower priority for memory scanning

### 1.4 Hex-Encoded Private Key

Some wallets and tools display private keys as raw hex strings.

**Format:**
```
64 hexadecimal characters (optionally prefixed with "0x")
```

**Regex:**
```regex
(0x)?[0-9a-fA-F]{64}
```

**False Positive Considerations:**
- Extremely high false positive rate in memory dumps
- SHA-256 hashes, UUIDs, random nonces all match this pattern
- Only useful when found in context (adjacent to wallet file magic bytes, JSON structures, etc.)
- **Not recommended as standalone detection** -- use only with contextual anchors

---

## 2. Ethereum Private Key Formats

### 2.1 Raw 256-bit Private Key

Identical to Bitcoin's raw format: 32 bytes on secp256k1 curve.

**Format:**
```
32 bytes (256 bits), typically displayed as 64-character hex string
Often prefixed with "0x" in Ethereum tooling
```

**Hex Pattern:**
```regex
(0x)?[0-9a-fA-F]{64}
```

**Same false positive concerns as Bitcoin raw hex keys.**

### 2.2 Ethereum Keystore JSON (UTC Files)

Encrypted wallet files following the "Web3 Secret Storage Definition" (Version 3).

**File Naming Convention:**
```
UTC--<ISO-timestamp>--<ethereum-address>
Example: UTC--2015-08-11T06:13:53.359Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b
```

**JSON Structure (Version 3):**
```json
{
  "version": 3,
  "id": "<uuid>",
  "address": "<40-hex-char-ethereum-address>",
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": {
      "iv": "<hex-encoded-initialization-vector>"
    },
    "ciphertext": "<hex-encoded-encrypted-private-key>",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "salt": "<hex-encoded-salt>",
      "n": 262144,
      "r": 8,
      "p": 1
    },
    "mac": "<hex-encoded-keccak256-mac>"
  }
}
```

**Key Fields for Detection in Memory:**
- `"version": 3` or `"version":3`
- `"cipher": "aes-128-ctr"` or `"cipher":"aes-128-ctr"`
- `"kdf": "scrypt"` or `"kdf": "pbkdf2"`
- `"ciphertext":` followed by hex string
- `"mac":` followed by hex string

**Detection Regex (for JSON fragments in memory):**
```regex
"version"\s*:\s*3\s*,.*?"crypto"\s*:\s*\{.*?"cipher"\s*:\s*"aes-128-ctr"
```

**Or search for distinctive field combinations:**
```regex
"ciphertext"\s*:\s*"[0-9a-f]{64}"
"kdf"\s*:\s*"(scrypt|pbkdf2)"
```

**Encryption Details:**
- Cipher: AES-128-CTR (minimum required; replaced older AES-128-CBC)
- KDF: scrypt (default) or PBKDF2-SHA256
- MAC: Keccak-256 of (derived_key[16:32] + ciphertext)
- The ciphertext field contains the encrypted 32-byte private key
- Default scrypt parameters: n=262144, r=8, p=1 (geth default; n=8192 for lighter versions)
- PBKDF2 alternative: c=262144 iterations, prf=hmac-sha256

**Decryption Process (for forensic validation):**
```
1. Derive key: scrypt(password, salt, n, r, p, dklen=32) -> derived_key[32 bytes]
2. Verify MAC: keccak256(derived_key[16:32] + ciphertext) == stored mac?
   If no: wrong password / corrupted data
3. Decrypt: AES-128-CTR(key=derived_key[0:16], iv=cipherparams.iv, data=ciphertext)
   -> 32-byte Ethereum private key
```

**Forensic Significance:**
- The keystore JSON structure is self-contained: finding it in memory means having the
  encrypted private key plus all parameters needed for offline password cracking
- MAC verification allows testing candidate passwords without full decryption
- The `address` field (if present) allows immediate attribution to on-chain activity

**Storage Locations:**
- Linux: `~/.ethereum/keystore/`
- Windows: `C:\Users\<User>\AppData\Roaming\Ethereum\keystore\`
- macOS: `~/Library/Ethereum/keystore/`

**False Positive Considerations:**
- Very low false positive rate due to structured JSON with specific field names
- The combination of `version: 3`, `cipher: aes-128-ctr`, `kdf`, and `mac` is highly distinctive
- **Excellent forensic target** -- highly specific structure

### 2.3 Ethereum Address Format

While not a private key, addresses are useful for confirming crypto activity.

**Format:**
```
42 characters: "0x" + 40 hexadecimal characters
```

**Regex:**
```regex
0x[0-9a-fA-F]{40}
```

**EIP-55 Checksum Validation:**
Mixed-case hex encoding where uppercase/lowercase is determined by keccak256 hash of the lowercase address. Provides error detection but is optional.

**False Positive Considerations:**
- Moderate false positive rate -- 40-char hex with `0x` prefix could match other hex data
- EIP-55 checksum validation significantly reduces false positives
- Useful as corroborating evidence alongside key findings

---

## 3. BIP-39 Seed Phrases (Mnemonics)

### 3.1 Overview

BIP-39 defines a standard method for generating mnemonic backup phrases for HD wallets.
A mnemonic phrase is a group of 12, 15, 18, 21, or 24 words from a fixed 2048-word list
that encodes entropy plus a checksum.

### 3.2 Entropy-to-Mnemonic Mapping

| Entropy (bits) | Checksum (bits) | Total Bits | Words |
|----------------|-----------------|------------|-------|
| 128            | 4               | 132        | 12    |
| 160            | 5               | 165        | 15    |
| 192            | 6               | 198        | 18    |
| 224            | 7               | 231        | 21    |
| 256            | 8               | 264        | 24    |

**Process:**
1. Generate ENT bits of random entropy
2. Compute checksum = first (ENT/32) bits of SHA-256(entropy)
3. Concatenate entropy + checksum
4. Split into 11-bit groups
5. Each 11-bit group is an index (0-2047) into the wordlist
6. Look up words and join with spaces

**Seed Derivation:**
- PBKDF2-HMAC-SHA512 with 2048 iterations
- Salt = "mnemonic" + optional passphrase
- Output = 512-bit (64-byte) seed
- This seed is then used for BIP-32 HD wallet derivation

### 3.3 Supported Languages (10 Official Wordlists)

| Language | Script | Notes |
|----------|--------|-------|
| **English** | Latin | De facto standard; universally supported |
| **Japanese** | Hiragana | Uses ideographic space (U+3000) separator |
| **Chinese (Simplified)** | CJK | Uses ASCII space (0x20) separator |
| **Chinese (Traditional)** | CJK | Uses ASCII space (0x20) separator |
| **Korean** | Hangul | CJK syllabic script |
| **Spanish** | Latin | No word overlap with other lists |
| **French** | Latin | 5-8 letters, no accents needed for first 4 chars |
| **Italian** | Latin | 4-8 letters, no accents or special chars |
| **Czech** | Latin | 4-8 letters, no diacritical marks |
| **Portuguese** | Latin | Brazilian/Portuguese spelling consistency |

**Important:** English is overwhelmingly the most common in practice. For memory scanning,
English should be the primary target. Other languages are secondary targets.

**Unicode Normalization:**
BIP-39 spec requires NFKD (Normalization Form Compatibility Decomposition) before PBKDF2.
Non-English wordlists may have Unicode normalization issues.

### 3.4 English Wordlist Properties

- Exactly 2048 words
- Alphabetically sorted
- First word: "abandon" (index 0)
- Last word: "zoo" (index 2047)
- **Unique 4-character prefix**: No two words share the same first 4 letters
- Word length: 3-8 characters (most are 4-8)
- No homophones, no similar-looking words, no profanity
- The wordlist has been stable since 2013 and will not change

**Sample Words (first 20):**
```
abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse,
access, accident, account, accuse, achieve, acid, acoustic, acquire, across, act
```

**Sample Words (last 5):**
```
zero, zone, zoo
```

### 3.5 Memory Detection Strategy

**Approach 1: Word Sequence Detection**
Search for sequences of BIP-39 words separated by spaces (or other common delimiters):
```
word1 word2 word3 ... word12  (or 15, 18, 21, 24)
```

**Approach 2: Sliding Window with BIP-39 Word Lookup**
1. Maintain a HashSet of all 2048 English BIP-39 words
2. Scan memory for ASCII/UTF-8 strings
3. Split by whitespace/delimiters
4. For each token, check if it exists in the BIP-39 wordlist
5. Track consecutive BIP-39 word matches
6. Alert when 12+ consecutive BIP-39 words found

**Regex for detecting potential mnemonic phrases (English):**
```regex
\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|...|zone|zoo)(\s+(abandon|ability|...|zoo)){11,23}\b
```

Note: Full regex with all 2048 words is impractical inline. Implementation should use a
HashSet lookup, not regex. The regex above is conceptual.

**Practical Detection Heuristic:**
```
1. Extract all printable ASCII strings from memory (min length 3)
2. For each string, tokenize by whitespace
3. Count consecutive tokens that are valid BIP-39 English words
4. If consecutive_count >= 12 AND consecutive_count IN {12, 15, 18, 21, 24}:
   a. Perform BIP-39 checksum validation
   b. If checksum passes: HIGH CONFIDENCE match
   c. If checksum fails but count >= 12: MEDIUM CONFIDENCE (partial/corrupted phrase)
```

**Checksum Validation:**
1. Convert words back to 11-bit indices
2. Concatenate all bits
3. Split: entropy bits = all except last (ENT/32) bits; checksum = last bits
4. Compute SHA-256 of entropy bytes
5. Compare first (ENT/32) bits of hash to checksum bits
6. Match confirms valid BIP-39 mnemonic

**False Positive Analysis:**
- Probability of 12 random English words all being in BIP-39 list:
  (2048/~170,000)^12 ~ extremely low
- With checksum validation: 1/16 chance a random 12-word sequence passes (for 128-bit)
- Combined: essentially zero false positives for checksum-validated 12+ word sequences
- **Very high precision detection target**

### 3.6 How Wallets Store Mnemonics in Memory

| Wallet | Storage Method |
|--------|---------------|
| **MetaMask** | Encrypted vault in browser localStorage; decrypted to JS heap when unlocked |
| **Electrum** | AES-256-CBC encrypted; decrypted briefly for signing only |
| **Bitcoin Core** | Does not use BIP-39 natively (uses its own seed format) |
| **Exodus** | AES-256 encrypted on device; HD wallet structure |
| **Hardware Wallets** | Seed stored on secure element; plaintext never exposed to host |
| **Mobile Wallets** | Typically encrypted with device PIN/biometric; may be in plaintext during setup |

**Critical forensic window:** During initial wallet setup, the mnemonic phrase is displayed
to the user in plaintext. This plaintext may persist in:
- Application memory (heap)
- Browser DOM/textarea (the "Demonic" vulnerability in MetaMask < 10.11.3)
- Clipboard buffer
- Screen capture memory
- Swap/pagefile
- Core dumps

---

## 4. BIP-32/44 HD Wallet Derivation

### 4.1 Extended Key Serialization Format

Extended keys (xprv/xpub) encode a key plus metadata needed for HD derivation.

**78-Byte Structure:**
```
Offset  Size    Field               Description
0-3     4       Version             Key type and network identifier
4       1       Depth               0x00 for master key; increments per level
5-8     4       Parent Fingerprint  0x00000000 for master key
9-12    4       Child Number        0x00000000 for master key; ser32(i) for child i
13-44   32      Chain Code          256-bit chain code for derivation
45-77   33      Key Data            0x00 || ser256(k) for private; serP(K) for public
```

**Serialization:**
```
78 bytes raw -> + 4-byte checksum (double SHA-256) -> Base58 encoding -> 111 characters
```

### 4.2 Version Bytes & Prefixes

| Version (hex) | Prefix | Type | Network | Script Type |
|---------------|--------|------|---------|-------------|
| `0x0488ADE4` | `xprv` | Private | Mainnet | P2PKH / P2SH (BIP-44) |
| `0x0488B21E` | `xpub` | Public | Mainnet | P2PKH / P2SH (BIP-44) |
| `0x049D7878` | `yprv` | Private | Mainnet | P2WPKH-in-P2SH (BIP-49) |
| `0x049D7CB2` | `ypub` | Public | Mainnet | P2WPKH-in-P2SH (BIP-49) |
| `0x04B2430C` | `zprv` | Private | Mainnet | P2WPKH (BIP-84) |
| `0x04B24746` | `zpub` | Public | Mainnet | P2WPKH (BIP-84) |
| `0x0488ADE4` | `Yprv` | Private | Mainnet | P2WSH-in-P2SH (multisig) |
| `0x0488B21E` | `Ypub` | Public | Mainnet | P2WSH-in-P2SH (multisig) |
| `0x02AA7ED3` | `Zprv` | Private | Mainnet | P2WSH (multisig) |
| `0x02AA7A99` | `Zpub` | Public | Mainnet | P2WSH (multisig) |
| `0x04358394` | `tprv` | Private | Testnet | - |
| `0x043587CF` | `tpub` | Public | Testnet | - |

### 4.3 Detection Patterns

**Regex for extended private keys:**
```regex
(xprv|yprv|zprv|tprv|Yprv|Zprv)[1-9A-HJ-NP-Za-km-z]{107,108}
```

**Regex for extended public keys:**
```regex
(xpub|ypub|zpub|tpub|Ypub|Zpub)[1-9A-HJ-NP-Za-km-z]{107,108}
```

**Combined (any extended key):**
```regex
(xprv|xpub|yprv|ypub|zprv|zpub|tprv|tpub|Yprv|Ypub|Zprv|Zpub)[1-9A-HJ-NP-Za-km-z]{107,108}
```

**Validation (post-regex):**
1. Base58-decode the string (should yield 82 bytes: 78 + 4 checksum)
2. Verify checksum: first 4 bytes of SHA256(SHA256(first 78 bytes))
3. Verify version bytes match known prefixes
4. For private keys: verify byte 45 is 0x00 (private key padding)
5. For private keys: verify key value (bytes 46-77) is in [1, n-1]

**False Positive Analysis:**
- The 4-character prefix (`xprv`, `xpub`, etc.) is highly distinctive
- Combined with exact length (111 chars) and Base58Check checksum: virtually zero false positives
- **Highest priority detection target** -- finding an xprv compromises ALL derived keys

### 4.4 BIP-44 Derivation Paths

Standard path format: `m / purpose' / coin_type' / account' / change / index`

| Standard | Purpose | Path Prefix | Key Prefix |
|----------|---------|-------------|------------|
| BIP-44 | 44' | `m/44'/0'/...` | xprv/xpub |
| BIP-49 | 49' | `m/49'/0'/...` | yprv/ypub |
| BIP-84 | 84' | `m/84'/0'/...` | zprv/zpub |
| BIP-86 | 86' | `m/86'/0'/...` | xprv/xpub (Taproot, no unique prefix) |

**Derivation path strings in memory:**
```regex
m/\d{1,3}'/\d{1,5}'/\d{1,5}'(/[01]/\d{1,10})?
```

Finding derivation path strings in memory is corroborating evidence of wallet activity.

### 4.5 Chain Code Importance

The 32-byte chain code is critical for HD derivation. If an attacker obtains:
- Extended public key (xpub) + any child private key = ALL private keys in that subtree
- This makes chain codes high-value forensic targets
- Chain codes are always present alongside extended keys (bytes 13-44 in the 78-byte structure)

---

## 5. Other Blockchain Private Key Formats

### 5.1 Solana (Ed25519)

**Key Characteristics:**
- Curve: Ed25519 (Twisted Edwards curve)
- Private key: 32 bytes (seed)
- Public key: 32 bytes
- "Secret key" (as exported by wallets): 64 bytes = private key (32) + public key (32)

**File Formats:**

| Format | Used By | Structure |
|--------|---------|-----------|
| JSON Uint8 Array | Solana CLI (`~/.config/solana/id.json`) | `[u8; 64]` as JSON array of integers |
| Base58 String | Phantom Wallet | Base58-encoded 64-byte keypair |
| Raw Bytes | In-memory | 64 contiguous bytes |

**Derivation Path (BIP-44):** `m/44'/501'/0'/0'`

**Detection Patterns:**

For JSON array format:
```regex
\[\s*\d{1,3}(\s*,\s*\d{1,3}){63}\s*\]
```
(Array of exactly 64 integers, each 0-255)

For Base58-encoded secret key:
- 87-88 character Base58 string (64 bytes Base58-encoded)
- No distinctive prefix character

**Validation:**
1. Decode the 64-byte secret key
2. First 32 bytes = private key seed
3. Last 32 bytes = public key
4. Derive public key from private key seed using Ed25519
5. Verify derived public key matches stored public key (bytes 32-63)
6. This cross-validation is highly reliable

**False Positive Considerations:**
- JSON array format: Low false positive (specific pattern of 64 integers)
- Base58 format: Moderate false positives without cross-validation
- With Ed25519 public key verification: very low false positives
- Solana public keys are also 32-byte Base58 strings (32-44 chars)

### 5.2 Polkadot (sr25519 / Ed25519)

**Key Characteristics:**
- Default curve: sr25519 (Schnorrkel/Ristretto)
- Alternative: Ed25519
- Private key seed: 32 bytes
- Public key: 32 bytes
- Address encoding: SS58 (Base58 variant with network-specific prefix)

**SS58 Address Format:**
```
[network-prefix-byte(s)] + [32-byte-public-key] + [checksum]
```

**Network Prefixes:**
- Polkadot: `1` (prefix byte 0)
- Kusama: starts with capital letter (prefix byte 2)
- Generic Substrate: `5` (prefix byte 42)

**Address Regex:**
```regex
[1-9A-HJ-NP-Za-km-z]{46,48}
```

**Key Storage:**
- Substrate wallets use `SecretKey` struct: 64-byte MiniSecretKey or SecretKey
- SURI (Secret URI) format: `//hard/soft///password` or raw hex seed

**Detection Patterns:**
- Look for SS58-encoded addresses starting with known network prefixes
- Polkadot addresses: `1[1-9A-HJ-NP-Za-km-z]{45,47}`
- Kusama addresses: `[A-Z][1-9A-HJ-NP-Za-km-z]{45,47}`
- Substrate generic: `5[1-9A-HJ-NP-Za-km-z]{45,47}`

**False Positive Considerations:**
- SS58 addresses are moderate-length Base58 strings; some false positives
- SS58 includes a checksum (last 2 bytes of blake2b hash) for validation

### 5.3 Cosmos (secp256k1)

**Key Characteristics:**
- Default curve: secp256k1 (same as Bitcoin)
- Private key: 32 bytes
- Public key: 33 bytes (compressed secp256k1)
- Address: 20 bytes, Bech32-encoded with chain-specific prefix

**Address Formats:**
| Chain | Prefix | Example |
|-------|--------|---------|
| Cosmos Hub | `cosmos1` | `cosmos1...` |
| Osmosis | `osmo1` | `osmo1...` |
| Juno | `juno1` | `juno1...` |
| Secret Network | `secret1` | `secret1...` |

**Address Regex:**
```regex
(cosmos|osmo|juno|secret|terra|akash|evmos|kava|sei|celestia|injective|stargaze)1[a-z0-9]{38}
```

**Detection Patterns:**
- Bech32-encoded addresses are distinctive: lowercase only, human-readable prefix + `1` separator
- Private keys are standard 32-byte secp256k1 (same as Bitcoin)
- Look for Bech32 address strings as corroborating evidence

**Bech32 Validation:**
Bech32 includes a 6-character checksum; invalid checksums indicate false positives.

### 5.4 Monero (EdDSA / Ed25519)

**Key Characteristics:**
- Curve: Ed25519 (Twisted Edwards)
- **Two private keys per wallet:**
  - Private spend key: 256 bits (32 bytes), reduced modulo l
  - Private view key: 256 bits (32 bytes), derived from spend key via Keccak-256
- Two corresponding public keys: 32 bytes each
- Curve order l: 2^252 + 27742317777372353535851937790883648493

**Monero-Specific Mnemonic:**
- Uses its own 1626-word wordlist (NOT BIP-39)
- 25-word mnemonic (24 words + 1 checksum word)
- The mnemonic encodes only the private spend key
- The private view key is deterministically derived: view_key = Keccak-256(spend_key) mod l

**Address Format (Standard):**
```
Network byte (1) + Public spend key (32) + Public view key (32) + Checksum (4) = 69 bytes
Base58 encoded in 8-byte blocks -> always exactly 95 characters
Starts with '4' (mainnet standard) or '8' (mainnet subaddress)
```

**Monero Base58:**
- Same alphabet as Bitcoin: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
- Encoded in 8-byte blocks (8 bytes -> 11 Base58 chars) + 5-byte final block (-> 7 chars)
- 8 * 11 + 7 = 95 characters always

**Detection Patterns:**

Standard address regex:
```regex
4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}
```

Integrated address (with embedded payment ID):
```regex
4[1-9A-HJ-NP-Za-km-z]{105}
```
(106 characters total)

Private key (hex):
```regex
[0-9a-fA-F]{64}
```
(Same as any 32-byte hex; requires context)

**Forensic Tool: MoeyEx**
- Volatility plugin for Monero wallet memory forensics
- Scans for `account_base` instances in memory dumps
- Verifies candidates by deriving Ed25519 public key from private key and comparing
- Can detect keys even when encrypted with passphrase (XOR obfuscation in memory)

**Encryption in Memory:**
- Spend key is XOR-encrypted in memory using ChaCha20-derived key from passphrase
- Initialization vector stored in `m_encryption_iv` field of `account_base` class
- Public keys and view keys may remain in plaintext

**False Positive Considerations:**
- Monero addresses (95 chars starting with '4') have moderate specificity
- Raw hex private keys: very high false positive rate (need context)
- MoeyEx-style structural scanning: very low false positives (Ed25519 derivation verification)

### 5.5 Ripple / XRP (secp256k1 / Ed25519)

**Key Characteristics:**
- Two supported algorithms: secp256k1 (default in rippled) and Ed25519
- Seed: 16 bytes of entropy
- Seed encoding: Base58 with XRP-specific alphabet, prefixed with 's'
- Ed25519 public keys: prefixed with byte 0xED to distinguish from secp256k1

**XRP Base58 Alphabet (differs from Bitcoin!):**
```
rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
```

**Seed Format:**
```
Base58Check encoding of: [version_byte] + [16-byte entropy]
Result: starts with 's' (e.g., "snoPBrXt...")
```

**Detection Patterns:**

XRP Seed regex:
```regex
s[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{28,29}
```

XRP Classic Address regex:
```regex
r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}
```

**Important:** XRP uses a DIFFERENT Base58 alphabet than Bitcoin. The character set mapping
is completely different, so Bitcoin Base58 decoding will not work for XRP.

**False Positive Considerations:**
- The 's' prefix for seeds is common; moderate false positives from regex alone
- Base58Check checksum verification significantly reduces false positives
- Different Base58 alphabet means XRP strings look slightly different from Bitcoin strings

### 5.6 Cardano (Extended Ed25519)

**Key Characteristics:**
- Curve: Ed25519 (BIP32-Ed25519 for HD derivation)
- Uses extended keys for HD wallets

**Key Formats:**

| Type | Size | Structure |
|------|------|-----------|
| Normal signing key | 32 bytes | Raw Ed25519 private key |
| Normal verification key | 32 bytes | Raw Ed25519 public key |
| Extended signing key | 96 bytes | 64-byte extended private key + 32-byte chain code |
| Extended verification key | 64 bytes | 32-byte public key + 32-byte chain code |
| Byron legacy | 128 bytes | 64-byte ext private key + 32-byte public key + 32-byte chain code |

**Address Encoding:**
- Byron era: Base58 (CBOR-encoded binary objects)
- Shelley era: Bech32 with prefix `addr` (mainnet) or `addr_test` (testnet)
- Stake addresses: Bech32 with prefix `stake`

**Key Encoding (CIP-16):**
- Bech32 with prefixes:
  - `*_sk` -- signing (private) key
  - `*_vk` -- verification (public) key
  - `*_xsk` -- extended signing key
  - `*_xvk` -- extended verification key
  - `root_xsk` -- root extended signing key

**Derivation Paths:**
- Byron: `m/44'/1815'/...` (purpose 44, coin type 1815)
- Shelley: `m/1852'/1815'/...` (purpose 1852, the year Ada Lovelace died)

**Detection Patterns:**

Shelley address regex:
```regex
addr1[a-z0-9]{53,}
```

Bech32 key regex:
```regex
(root_xsk|acct_xsk|addr_xsk|stake_xsk|addr_sk|stake_sk)[1-9a-z]{50,}
```

Byron address (Base58):
```regex
DdzFF[1-9A-HJ-NP-Za-km-z]{50,100}
```

**Address Hashing:**
Shelley addresses use blake2b-224 hash of Ed25519 verification keys.

**False Positive Considerations:**
- Bech32 keys with specific prefixes (`addr1`, `root_xsk`) are highly distinctive
- Byron Base58 addresses with `DdzFF` prefix are distinctive
- Low false positive rate for both formats

---

## 6. Wallet Software Memory Patterns

### 6.1 Bitcoin Core

**Source Code Structs (from `src/key.h` and `src/wallet/crypter.h`):**

`CKey` -- the core private key container:
```cpp
// src/key.h
class CKey {
public:
    static const unsigned int SIZE            = 279;  // Full DER-encoded size
    static const unsigned int COMPRESSED_SIZE = 214;
private:
    using KeyType = std::array<unsigned char, 32>;  // Raw 32-byte secp256k1 key
    KeyType keydata;                                 // The actual key material
    bool fValid{false};                              // Is this key initialized?
    bool fCompressed{false};                         // Compressed public key?
    // Uses secure_allocator to prevent swapping to disk
};

// Serialized private key type (DER-encoded, variable length)
typedef std::vector<unsigned char, secure_allocator<unsigned char>> CPrivKey;
```

`CMasterKey` -- wallet encryption master key:
```cpp
// src/wallet/crypter.h
namespace wallet {
const unsigned int WALLET_CRYPTO_KEY_SIZE = 32;   // AES-256 key size
const unsigned int WALLET_CRYPTO_SALT_SIZE = 8;   // Salt for key derivation
const unsigned int WALLET_CRYPTO_IV_SIZE = 16;    // AES-CBC IV size

class CMasterKey {
public:
    std::vector<unsigned char> vchCryptedKey;       // Encrypted master key bytes
    std::vector<unsigned char> vchSalt;             // Random 8-byte salt
    unsigned int nDerivationMethod;                 // 0 = EVP_sha512()
    unsigned int nDeriveIterations;                 // Default: 25000
    std::vector<unsigned char> vchOtherDerivationParameters;  // Reserved
};
}
```

`CCrypter` -- the AES-256-CBC encryption/decryption context:
```cpp
class CCrypter {
private:
    std::vector<unsigned char, secure_allocator<unsigned char>> vchKey;  // 32 bytes
    std::vector<unsigned char, secure_allocator<unsigned char>> vchIV;   // 16 bytes
    bool fKeySet;
    int BytesToKeySHA512AES(span<const unsigned char> salt,
                            const SecureString& key_data,
                            int count, unsigned char* key, unsigned char* iv) const;
public:
    bool SetKeyFromPassphrase(const SecureString& key_data,
                              span<const unsigned char> salt,
                              unsigned int rounds,
                              unsigned int derivation_method);
    bool Encrypt(const CKeyingMaterial& plaintext, vector<unsigned char>& ciphertext) const;
    bool Decrypt(span<const unsigned char> ciphertext, CKeyingMaterial& plaintext) const;
    void CleanKey() { memory_cleanse(vchKey.data(), vchKey.size());
                      memory_cleanse(vchIV.data(), vchIV.size());
                      fKeySet = false; }
};
```

**Encryption Architecture:**
```
                        User Passphrase
                              |
                    SHA-512 + EVP_BytesToKey
                    (25000+ rounds, 8-byte salt)
                              |
                         Derived Key (32 bytes) + IV (16 bytes)
                              |
                       AES-256-CBC Decrypt
                              |
                    CMasterKey.vchCryptedKey (48 bytes: 32 + PKCS#7 padding)
                              |
                         Master Key (32 bytes)
                              |
         +--------------------+--------------------+
         |                    |                    |
   AES-256-CBC           AES-256-CBC          AES-256-CBC
   IV=Hash(PubKey1)[:16] IV=Hash(PubKey2)[:16] ...
         |                    |                    |
   Encrypted CKey #1     Encrypted CKey #2    ...
   (48 bytes each: 32-byte privkey + PKCS#7 0x10 padding)
```

**Per-Key IV Derivation:**
- IV for each private key = first 16 bytes of SHA256(SHA256(public_key))
- All CKeys in one wallet share the same master key
- Correctly decrypted CKey ends with sixteen 0x10 bytes (PKCS#7 padding)

**wallet.dat Berkeley DB Structure:**
```
Magic bytes: 0x00061561 (big-endian) or 0x61150600 (little-endian)
Key-value store with record types:
  "mkey"  -> CMasterKey (encrypted master key + salt + params)
  "ckey"  -> CPubKey + encrypted_private_key (48 bytes AES-256-CBC)
  "key"   -> CPubKey + CPrivKey (unencrypted wallet -- legacy only)
  "wkey"  -> CPubKey + CWalletKey (deprecated)
  "name"  -> address label
  "tx"    -> CWalletTx (transaction records)
  "pool"  -> CKeyPool (pre-generated key pool, default 100 keys)
```

**Key Pool:** Bitcoin Core pre-generates 100 keys (configurable via `-keypool`) and
stores them in the wallet. These keys exist even before any transactions, and are
consumed as change addresses are needed. All pool keys are encrypted with the same
master key if the wallet is encrypted.

**Memory Behavior:**
- Encrypted wallets: **No unencrypted private keys in RAM** when locked
- Encrypted wallets: Passphrase also NOT found in memory
- Public keys and addresses: ALWAYS present in process memory (Berkeley DB in-memory cache)
- After unlocking: decrypted keys available for the timeout period, then cleared
- After wallet.dat decryption timeout: keys re-encrypted in memory
- `secure_allocator` locks pages with `mlock()` to prevent swap-out

**Forensic Approach:**
- Target public keys/addresses for evidence of wallet usage (always available)
- Catch the decryption window if wallet was recently unlocked
- `walletpassphrase <passphrase> <timeout>` RPC leaves keys decrypted for duration
- **Key persistence:** After application termination, traces overwritten within ~6 minutes
- Process-specific dump (ProcDump) is faster and more targeted than full RAM capture
- Search for `mkey` and `ckey` byte sequences in memory for wallet structure fragments

**Detection Targets:**
```
"mkey" byte sequence -- encrypted master key record
"ckey" byte sequence -- encrypted private key entries
"key\x00" byte sequence -- unencrypted private key (legacy unencrypted wallets!)
Berkeley DB magic: 0x00061561 (big-endian) or 0x61150600 (little-endian)
Berkeley DB page size: typically 4096 bytes
Wallet file name: "wallet.dat" as ASCII string in memory
```

### 6.2 Electrum

**Encryption:**
- AES-256-CBC for seed and private key encryption
- ECIES (asymmetric) for wallet file encryption (since v2.8)
- Password is NOT kept in memory after encryption
- Keys decrypted only briefly during transaction signing

**Electrum Seed Version System (since v2.0):**
- Electrum uses BIP-39's 2048-word English wordlist but NOT the BIP-39 derivation algorithm
- Instead, seed validity is determined by hashing: `HMAC-SHA512("Seed version", mnemonic)`
- The version byte(s) in the hash prefix determine the wallet type (standard, segwit, 2FA, etc.)
- This means Electrum seeds are NOT interchangeable with BIP-39-compatible wallets
- Detection: same word-based scanning as BIP-39 but checksum validation differs

**Wallet File Format:**
Electrum wallet is a JSON file with known structure:
```json
{
    "keystore": {
        "type": "bip32",
        "xprv": "xprv9s21ZrQH143K...",
        "xpub": "xpub661MyMwAqRbc...",
        "seed": "<encrypted-seed-phrase>"
    },
    "wallet_type": "standard",
    "use_encryption": true
}
```

**Memory Behavior:**
- Seed phrase found in memory ONLY immediately after wallet initialization (confirmed by
  Van Der Horst et al. 2017 and replicated in 2022 live forensics study)
- No private keys or passphrase found in memory during normal operation
- Public keys, addresses, labels, and transaction IDs persist in process memory
- Master public key (xpub) always present during session
- Wallet file JSON structure loaded into Python heap; JSON keys/tags serve as memory anchors
- Encrypted private keys stored in RAM may be vulnerable: researchers leveraged a weakness
  to perform ~2.4 trillion password guesses against Electrum's in-memory encrypted keys

**Wallet File Detection:**
- JSON format with known field structures
- Look for strings like `"seed"`, `"keystore"`, `"xprv"`, `"xpub"`, `"wallet_type"` in JSON context
- File paths: `~/.electrum/wallets/` (Linux), `%APPDATA%\Electrum\wallets\` (Windows),
  `~/Library/Application Support/Electrum/wallets/` (macOS)

### 6.3 MetaMask (Browser Extension)

**Architecture:**
- `KeyringController` manages encrypted vault
- Two-tier storage:
  - `this.store` (persistent): encrypted vault in `chrome.storage.local`
  - `this.memStore` (in-memory): decrypted keys in JavaScript heap

**Encryption Details:**
- Desktop extension: PBKDF2 with 10,000 iterations + AES-GCM (via `browser-passworder`)
- Mobile app: PBKDF2 with 5,000 iterations + AES-CBC
- Vault is a JSON blob encrypted with password-derived symmetric key

**Vault JSON Formats (Old vs New):**
```json
// Old format (pre-KeyMetadata):
{"data": "<base64-ciphertext>", "iv": "<hex>", "salt": "<hex>"}

// New format (with dynamic iterations -- hashcat -m 26620):
{"data": "<base64-ciphertext>", "iv": "<hex>",
 "keyMetadata": {"algorithm": "PBKDF2", "params": {"iterations": <N>}},
 "salt": "<hex>"}
```
Old vault hashes can be cracked with `hashcat -m 26600`; new vaults with dynamic
iterations require the custom `hashcat -m 26620` kernel.

**Firefox-Specific Vault Recovery:**
- Extension data stored in `storage/default/moz-extension+<uuid>/idb/` as binary files
- Data may be Snappy-compressed (look for `sNaPpY` / hex `FF060000734E6150705900`)
- Use `snappy-fox` to decompress before vault extraction

**Memory Behavior:**
- When LOCKED: only encrypted vault exists (in localStorage and memory)
- When UNLOCKED: decrypted private keys in `this.memStore` (JavaScript heap)
- **Critical:** Decrypted keys remain in JS heap until extension is locked
- After locking: keys should be cleared from memStore, but JS GC is non-deterministic

**Vault Location on Disk:**
- Chrome/Windows: `C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn`
- The extension ID `nkbihfbeogaeaoehlefnkodbefgpgknn` is MetaMask's

**Detection in Memory Dumps:**

Vault JSON structure:
```regex
\{"data"\s*:\s*"[A-Za-z0-9+/=]+".*?"iv"\s*:\s*"[A-Za-z0-9+/=]+".*?"salt"\s*:\s*"[A-Za-z0-9+/=]+"\}
```

KeyringController state:
```regex
"KeyringController"\s*:\s*\{.*?"vault"\s*:\s*"
```

Decrypted HD keyring in memory (when unlocked):
```regex
"hdPath"\s*:\s*"m/44'/60'/0'/0"
"mnemonic"\s*:\s*"[a-z]+(\s+[a-z]+){11,23}"
"numberOfAccounts"\s*:\s*\d+
```

**Historical Vulnerability: "Demonic" (CVE-2022-32969)**
- Affected MetaMask < 10.11.3
- Mnemonic stored in browser's Session Restore cache as plaintext
- `textarea` tag content cached to disk by browser
- Plaintext seed phrase recoverable from disk even after browser closed

### 6.4 Exodus

**Encryption:**
- AES-256 encryption for private keys on device
- HD wallet structure (BIP-44 compliant)
- Client-side encryption; Exodus never has access to user keys

**Memory Behavior:**
- Research found artifacts persist even after uninstallation (until system restart)
- Passwords found in volatile memory after uninstallation, before restart

**Detection:**
- Look for Exodus-specific file paths and process names
- Wallet data in `%APPDATA%/Exodus/` (Windows) or `~/Library/Application Support/Exodus/` (macOS)

### 6.5 Trust Wallet (Mobile)

**Key Storage:**
- Secret recovery phrase and private keys encrypted in both Android and iOS apps
- Uses platform-specific secure storage (Keychain on iOS, Keystore on Android)

**Known Vulnerabilities:**
- 2022 browser extension vulnerability: 32-bit entropy generator used for wallet creation
  (Nov 14-23, 2022); allowed private key reconstruction from public addresses
- Mobile app: keywords and private keys encrypted; other artifacts in plaintext

**Detection:**
- Mobile memory dumps: look for app-specific data structures
- Browser extension: similar to MetaMask vault structure

### 6.6 Phantom Wallet (Browser Extension -- Solana/Multi-Chain)

**Architecture:**
- Similar to MetaMask: encrypted vault in browser extension storage
- Supports Solana, Ethereum, Bitcoin, Polygon, and Base
- Vault decryption key derived from user password

**Key Storage:**
- Ed25519 keypairs (Solana) and secp256k1 keys (EVM chains)
- Exports private keys as Base58-encoded 64-byte keypairs (Solana)
- Seed phrase follows BIP-39 standard (12/24 words)

**Memory Behavior:**
- When unlocked: decrypted Ed25519 keypairs in browser process memory
- Same JS GC non-determinism concerns as MetaMask
- Extension ID: `bfnaelmomeimhlpmgjnjophhpkkoljpa` (Chrome)

**Detection in Memory:**
- Similar vault JSON structure patterns as MetaMask
- Solana-specific: search for Base58 keypair strings (87-88 chars)
- HD path strings: `"m/44'/501'/0'/0'"` (Solana BIP-44 derivation)

### 6.7 Hardware Wallets (Ledger, Trezor)

**Key Point:** Hardware wallets never expose the raw private key/seed to the host computer.

**What IS Exposed in Host Computer Memory:**
- Extended public keys (xpub/ypub/zpub)
- Transaction data
- Device identifiers
- Passphrase (if entered on host, not on device)
- Communication protocol data (USB HID frames)

**FORESHADOW Research Findings:**
- Extended public keys, transaction history, and device IDs found in host memory
- Passphrases sometimes found in memory (depends on device/software)
- xpub recovery alone can deanonymize all past and future transactions
- Data may persist in memory even after client locks
- After ~6 minutes post-application termination, all traces overwritten

---

## 7. Existing Tools for Crypto Key Recovery

### 7.1 BTCRecover

- **Type:** Password/seed recovery tool (brute-force)
- **GitHub:** github.com/gurnec/btcrecover
- **Targets:** Bitcoin Core (wallet.dat), Electrum, MultiBit, Blockchain.com, Mycelium
- **Methods:** Dictionary attack, token-based password construction, typo permutations
- **Capabilities:** Password cracking (GPU-accelerated), seed phrase recovery with partial knowledge
- **Not:** A memory scanning tool; works on encrypted wallet files

### 7.2 Hashcat

- **Type:** General-purpose password cracker
- **Supports:** Bitcoin Core wallet.dat hash extraction and cracking
- **Method:** GPU-accelerated brute-force and rule-based attacks
- **Hash modes:** 11300 (Bitcoin/Litecoin wallet.dat), others for Ethereum keystores

### 7.3 AESKeyFind

- **Type:** Memory forensics tool for AES key schedule detection
- **Method:** Scans memory dumps for AES key schedule byte patterns
- **Relevance:** Can find AES keys used to encrypt wallet private keys
- **How:** AES expanded key schedules have mathematical relationships between
  consecutive round keys that are statistically improbable in random data
- **False positives:** Very low; AES key schedule patterns are highly distinctive

### 7.4 CryKeX

- **Type:** Linux memory cryptographic key extractor
- **GitHub:** github.com/cryptolok/CryKeX
- **Method:** Dumps live process memory, searches for entropy patterns matching key lengths
- **Approach:** Find high-entropy regions of correct key length, then verify using C data
  type analysis of surrounding memory structures

### 7.5 FORESHADOW (Volatility Plugin)

- **Type:** Memory forensics framework for hardware cryptocurrency wallets
- **Method:** YARA-based pattern scanning of memory dumps
- **Targets:** Ledger and Trezor hardware wallet companion software
- **Finds:** Extended public keys, transaction history, device IDs, passphrases

### 7.6 MoeyEx (Volatility Plugin)

- **Type:** Monero-specific memory forensics tool
- **Method:** Scans for `account_base` C++ class instances in memory
- **Validation:** Derives Ed25519 public key from candidate private key, compares to stored public key
- **Handles:** XOR-encrypted spend keys in memory (ChaCha20-derived encryption)

### 7.7 BTCscan

- **Type:** Python script for Bitcoin artifact extraction
- **Method:** Regex-based scanning for Base58Check strings
- **Targets:** Bitcoin addresses, WIF private keys
- **Validates:** Base58Check checksum for false positive reduction

### 7.8 FEA (Forensics Enhanced Analysis)

- **Type:** Autopsy plugin
- **Method:** Regex + validation for Bitcoin addresses and private keys
- **Extra:** False positive reduction (marked ~40% of regex matches as false positives)

### 7.9 Bulk Extractor

- **Type:** General forensic artifact scanner
- **Capabilities:** URLs, email addresses, credit card numbers, cryptocurrency addresses
- **Method:** Pattern matching across disk images and memory dumps

### 7.10 Volatility Framework

- **Type:** Memory forensics framework
- **Plugins:** DumpCerts (RSA keys), custom plugins for crypto keys
- **Approach:** Process memory mapping, string searches, YARA rules

---

## 8. Detection Signatures & Implementation Guide

### 8.1 Priority-Ranked Detection Targets

Listed by detection reliability (precision) and forensic value:

| Priority | Target | Precision | Forensic Value | Method |
|----------|--------|-----------|---------------|--------|
| **P0** | BIP-39 mnemonic phrase (12-24 words) | Very High | Critical (master seed) | Wordlist + checksum |
| **P0** | Extended private keys (xprv/yprv/zprv) | Very High | Critical (HD root) | Prefix + Base58Check |
| **P1** | WIF private keys (5/K/L prefix) | Very High | High (individual key) | Prefix + Base58Check |
| **P1** | Ethereum keystore JSON | Very High | High (encrypted key) | JSON structure match |
| **P1** | MetaMask vault data | High | High (encrypted seed) | JSON structure match |
| **P2** | Solana keypair (64-byte JSON array) | High | High | Array pattern + Ed25519 verify |
| **P2** | Monero addresses (95 chars, '4' prefix) | High | Medium (address only) | Prefix + length |
| **P2** | Cardano Bech32 keys/addresses | High | Medium-High | Bech32 prefix + checksum |
| **P2** | Bitcoin/Ethereum addresses | Medium | Low (public info) | Pattern match + checksum |
| **P3** | Raw 32-byte hex private keys | Very Low | High if valid | Context-dependent only |
| **P3** | Mini private keys | Medium | Medium | 'S' prefix + SHA256 check |
| **P3** | XRP seeds | Medium | High | 's' prefix + Base58Check |

### 8.2 Detailed Detection Signatures

#### BIP-39 Mnemonic Phrases

**Implementation Strategy:**
```rust
// Precompute HashSet of all 2048 English BIP-39 words
static BIP39_WORDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    include_str!("bip39_english.txt")
        .lines()
        .collect()
});

fn scan_for_mnemonics(data: &[u8]) -> Vec<MnemonicMatch> {
    let text = extract_printable_strings(data, min_len=3);
    for string in text {
        let words: Vec<&str> = string.split_whitespace().collect();
        let mut consecutive = 0;
        let mut start_idx = 0;
        for (i, word) in words.iter().enumerate() {
            if BIP39_WORDS.contains(word.to_lowercase().as_str()) {
                if consecutive == 0 { start_idx = i; }
                consecutive += 1;
            } else {
                if consecutive >= 12 {
                    // Validate checksum for [12, 15, 18, 21, 24] word sequences
                    validate_and_report(&words[start_idx..start_idx+consecutive]);
                }
                consecutive = 0;
            }
        }
    }
}
```

**Validation:**
1. Convert words to indices (position in sorted wordlist)
2. Convert indices to 11-bit binary representation
3. Concatenate all bits
4. Last ENT/32 bits = checksum; remaining = entropy
5. SHA-256(entropy) first bits should match checksum

#### WIF Private Keys

**Pattern:** `[5KL][1-9A-HJ-NP-Za-km-z]{50,51}`

**Validation Pipeline:**
```
1. Regex match -> candidate string
2. Base58 decode -> raw bytes
3. Length check: 37 bytes (uncompressed) or 38 bytes (compressed)
4. Version byte check: 0x80 (mainnet) or 0xEF (testnet)
5. Checksum verify: SHA256(SHA256(payload)) first 4 bytes == last 4 bytes
6. Private key range check: 1 <= key < n (secp256k1 order)
```

#### Extended Keys (xprv/xpub/yprv/etc.)

**Pattern:** `(xprv|xpub|yprv|ypub|zprv|zpub|tprv|tpub)[1-9A-HJ-NP-Za-km-z]{107,108}`

**Validation Pipeline:**
```
1. Regex match -> candidate string (111 chars)
2. Base58 decode -> 82 bytes (78 payload + 4 checksum)
3. Checksum verify: SHA256(SHA256(first 78 bytes)) first 4 bytes
4. Version bytes match known set (see table in 4.2)
5. For private keys: byte[45] == 0x00 (padding byte)
6. For private keys: key value (bytes 46-77) in [1, n-1]
7. Depth byte (byte[4]) in [0, 255] (usually 0-6 in practice)
```

#### Ethereum Keystore JSON

**Detection Strategy:**
Scan for JSON fragments containing distinctive field combinations:

```rust
fn scan_for_eth_keystore(data: &[u8]) -> Vec<KeystoreMatch> {
    let text = String::from_utf8_lossy(data);

    // Look for version 3 keystore markers
    let markers = [
        r#""version":3"#, r#""version": 3"#,
        r#""cipher":"aes-128-ctr""#, r#""cipher": "aes-128-ctr""#,
        r#""kdf":"scrypt""#, r#""kdf": "scrypt""#,
        r#""kdf":"pbkdf2""#, r#""kdf": "pbkdf2""#,
    ];

    // If 2+ markers found within 2KB window, attempt JSON extraction
    // Parse JSON and validate all required fields present
}
```

**Required fields for valid keystore:**
- `version` == 3
- `crypto.cipher` == "aes-128-ctr"
- `crypto.ciphertext` (hex string, typically 64 chars)
- `crypto.kdf` == "scrypt" or "pbkdf2"
- `crypto.kdfparams` with appropriate sub-fields
- `crypto.mac` (hex string, 64 chars = Keccak-256 output)

#### MetaMask Vault

**Detection Strategy:**
Search for the MetaMask vault JSON structure in browser storage areas:

```regex
\{"data"\s*:\s*"[A-Za-z0-9+/=]+".*?"iv"\s*:\s*"[A-Za-z0-9+/=]+".*?"salt"\s*:\s*"[A-Za-z0-9+/=]+"\}
```

Also search for decrypted KeyringController state (if wallet was unlocked):
```regex
"mnemonic"\s*:\s*"[a-z ]{20,}"
"hdPath"\s*:\s*"m/44'/60'/0'/0"
```

#### Solana Keypair

**JSON Array Pattern:**
```regex
\[\s*\d{1,3}(\s*,\s*\d{1,3}){63}\s*\]
```

**Validation:**
1. Parse as array of 64 u8 values
2. Split: private_seed = bytes[0..32], public_key = bytes[32..64]
3. Derive Ed25519 public key from private_seed
4. Verify derived public key == stored public_key
5. This is an extremely strong validation (2^-256 false positive rate)

#### Monero Address

**Pattern:** `4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}`

**Validation:**
1. Monero Base58 decode (8-byte block scheme, NOT Bitcoin's Base58)
2. Verify 69 bytes: 1 (network) + 32 (spend pubkey) + 32 (view pubkey) + 4 (checksum)
3. Checksum: first 4 bytes of Keccak-256(first 65 bytes)

#### Bitcoin Addresses (Corroborating Evidence)

**Legacy (P2PKH):**
```regex
1[1-9A-HJ-NP-Za-km-z]{25,34}
```

**Script Hash (P2SH):**
```regex
3[1-9A-HJ-NP-Za-km-z]{25,34}
```

**Bech32 (Native SegWit):**
```regex
bc1[a-z0-9]{39,59}
```

**Validation:** Base58Check checksum (for legacy/P2SH) or Bech32 checksum (for native SegWit).

### 8.3 False Positive Mitigation Strategies

1. **Checksum Verification:** Always verify Base58Check/Bech32 checksums after regex match.
   This alone reduces false positives by ~99.99999% (2^-32 for 4-byte checksums).

2. **Elliptic Curve Point Verification:** For private keys, verify the derived public key
   is a valid point on the curve. For Ed25519, verify public key derivation matches.

3. **Context Analysis:** Check surrounding memory for:
   - Adjacent public keys
   - Wallet file headers/magic bytes
   - JSON structure markers
   - Known application data structures
   - Derivation path strings

4. **Entropy Analysis:** Valid private keys should have high Shannon entropy (~7.5-8.0 bits
   per byte for 32-byte keys). Low-entropy candidates are likely false positives.

5. **Length Constraints:** Enforce exact length requirements (not just minimum).
   WIF = exactly 51 or 52 chars; xprv = exactly 111 chars.

6. **Cross-Reference:** If both a private key and its corresponding public key/address
   are found in memory, confidence is much higher.

7. **Known Offset Patterns:** Wallet software stores keys at known structure offsets.
   Understanding the target wallet's data structures allows precise extraction.

### 8.4 YARA Rules for Cryptocurrency Key Detection

The following YARA rules can be used with memory forensics tools (Volatility 3's
`windows.yarascan` / `linux.yarascan` plugins, or standalone YARA scanning of raw
memory dumps). These complement the regex-based detection in the Rust scanner.

**Existing open-source YARA rule (Didier Stevens, via Manalyze):**
```yara
rule BitcoinAddress {
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
        $btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/
    condition:
        any of them
}
```

**WIF Private Key Detection:**
```yara
rule WIF_PrivateKey {
    meta:
        description = "Detects Bitcoin WIF private keys (mainnet)"
        author = "Issen"
        severity = "critical"
        false_positive_rate = "low -- Base58Check checksum validation recommended"
    strings:
        $wif_uncompressed = /5[HJK][1-9A-HJ-NP-Za-km-z]{49}/
        $wif_compressed = /[KL][1-9A-HJ-NP-Za-km-z]{51}/
    condition:
        any of them
}
```

**BIP-39 Mnemonic Phrase Detection (English):**
```yara
rule BIP39_Mnemonic_Phrase {
    meta:
        description = "Detects potential BIP-39 English mnemonic seed phrases"
        author = "Issen"
        severity = "critical"
        note = "Uses common BIP-39 bigrams; full 2048-word matching done in Rust scanner"
    strings:
        // Common seed phrase context markers
        $ctx_seed = "seed phrase" ascii nocase
        $ctx_mnemonic = "mnemonic" ascii nocase
        $ctx_recovery = "recovery phrase" ascii nocase
        $ctx_backup = "backup words" ascii nocase
        // BIP-39 word sequences (high-signal adjacent pairs from position 0-1)
        $pair_abandon_ability = "abandon ability" ascii
        $pair_abandon_able = "abandon able" ascii
        // First/last words as anchors (index 0 and 2047)
        $word_abandon = /\babandon\s+[a-z]{3,8}\s+[a-z]{3,8}/ ascii
        $word_zoo = /[a-z]{3,8}\s+[a-z]{3,8}\s+zoo\b/ ascii
        // JSON context (Electrum/MetaMask wallet structures)
        $json_mnemonic = /"mnemonic"\s*:\s*"[a-z]+(\s+[a-z]+){11,23}"/ ascii
        $json_seed = /"seed"\s*:\s*"[a-z]+(\s+[a-z]+){11,23}"/ ascii
    condition:
        any of ($ctx_*) or any of ($pair_*) or any of ($word_*) or any of ($json_*)
}
```

**Extended Key Detection (BIP-32 HD Wallets):**
```yara
rule BIP32_Extended_Keys {
    meta:
        description = "Detects BIP-32 extended private and public keys"
        author = "Issen"
        severity = "high"
    strings:
        $xprv = /xprv[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $xpub = /xpub[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $yprv = /yprv[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $ypub = /ypub[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $zprv = /zprv[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $zpub = /zpub[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $tprv = /tprv[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
        $tpub = /tpub[1-9A-HJ-NP-Za-km-z]{107,108}/ ascii
    condition:
        any of them
}
```

**Ethereum Keystore Detection:**
```yara
rule Ethereum_Keystore_V3 {
    meta:
        description = "Detects Ethereum V3 keystore JSON structures"
        author = "Issen"
        severity = "high"
    strings:
        $ver = /"version"\s*:\s*3/ ascii
        $cipher = /"cipher"\s*:\s*"aes-128-ctr"/ ascii
        $kdf_scrypt = /"kdf"\s*:\s*"scrypt"/ ascii
        $kdf_pbkdf2 = /"kdf"\s*:\s*"pbkdf2"/ ascii
        $ciphertext = /"ciphertext"\s*:\s*"[0-9a-f]{64}"/ ascii
        $mac = /"mac"\s*:\s*"[0-9a-f]{64}"/ ascii
    condition:
        $ver and $cipher and ($kdf_scrypt or $kdf_pbkdf2) and $ciphertext and $mac
}
```

**MetaMask Vault Detection:**
```yara
rule MetaMask_Vault {
    meta:
        description = "Detects MetaMask encrypted vault structures"
        author = "Issen"
        severity = "high"
    strings:
        // Old vault format
        $vault_old = /\{"data"\s*:\s*"[A-Za-z0-9+\/=]+".*?"iv"\s*:\s*"[A-Za-z0-9+\/=]+".*?"salt"\s*:\s*"[A-Za-z0-9+\/=]+"\}/ ascii
        // New vault format with KeyMetadata
        $vault_new = /"keyMetadata"\s*:\s*\{.*?"algorithm"\s*:\s*"PBKDF2"/ ascii
        // KeyringController context
        $keyring = /"KeyringController"\s*:\s*\{.*?"vault"/ ascii
        // Decrypted HD keyring (unlocked state -- critical finding)
        $hdpath_eth = /"hdPath"\s*:\s*"m\/44'\/60'\/0'\/0"/ ascii
        // MetaMask extension ID
        $ext_id = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
    condition:
        any of them
}
```

**Bitcoin Core wallet.dat Detection:**
```yara
rule Bitcoin_Core_WalletDB {
    meta:
        description = "Detects Bitcoin Core wallet.dat Berkeley DB structures in memory"
        author = "Issen"
        severity = "high"
    strings:
        // Berkeley DB 4.8 magic number (little-endian and big-endian)
        $bdb_magic_le = { 61 15 06 00 }
        $bdb_magic_be = { 00 06 15 61 }
        // wallet.dat record type markers
        $mkey = "mkey" ascii
        $ckey = "ckey" ascii
        $wkey = "wkey" ascii
        // Wallet file name in memory
        $wallet_dat = "wallet.dat" ascii
        // Bitcoin Core user agent strings (adjacent evidence)
        $ua_core = "/Satoshi:" ascii
    condition:
        ($bdb_magic_le or $bdb_magic_be) or
        ($mkey and $ckey) or
        ($wallet_dat and ($ckey or $mkey))
}
```

**Solana Keypair Detection:**
```yara
rule Solana_Keypair {
    meta:
        description = "Detects Solana keypair JSON arrays and derivation paths"
        author = "Issen"
        severity = "high"
    strings:
        // JSON array of 64 u8 values (Solana CLI format)
        $json_array = /\[\s*\d{1,3}(\s*,\s*\d{1,3}){63}\s*\]/ ascii
        // Solana BIP-44 derivation path
        $sol_path = "m/44'/501'" ascii
        // Solana CLI config path
        $sol_config = ".config/solana/id.json" ascii
    condition:
        any of them
}
```

**Monero Key Detection:**
```yara
rule Monero_Keys {
    meta:
        description = "Detects Monero wallet artifacts"
        author = "Issen"
        severity = "high"
    strings:
        // Monero standard address (95 chars starting with 4)
        $address = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        // Monero key labels in wallet files
        $spend_key = "spend_secret_key" ascii
        $view_key = "view_secret_key" ascii
        $mnemonic_label = "electrum_words" ascii  // Monero's mnemonic field name
        // 64-char hex key in context (spend or view key)
        $hex_key_ctx = /(spend|view).*?[0-9a-f]{64}/ ascii nocase
    condition:
        any of them
}
```

**Multi-Chain Entropy Detection (high-entropy 32-byte regions):**
```yara
rule HighEntropy_CryptoKey_Candidate {
    meta:
        description = "Detects high-entropy 32-byte regions near crypto context markers"
        author = "Issen"
        severity = "medium"
        note = "High false positive rate alone; only useful with contextual anchors"
    strings:
        $ctx_privkey = "private" ascii nocase
        $ctx_secret = "secret" ascii nocase
        $ctx_key = "key" ascii nocase
        $ctx_wallet = "wallet" ascii nocase
        $ctx_secp256k1 = "secp256k1" ascii
        $ctx_ed25519 = "ed25519" ascii
        $ctx_curve25519 = "curve25519" ascii
    condition:
        2 of them
}
```

**Usage with Volatility 3:**
```bash
# Scan process memory for crypto artifacts
vol3 -f memory.raw windows.yarascan --yara-file crypto_keys.yar
vol3 -f memory.raw windows.yarascan --yara-file crypto_keys.yar --pid <wallet_pid>

# Scan Linux memory dump
vol3 -f memory.raw linux.yarascan --yara-file crypto_keys.yar
```

**Note on YARA Limitations:**
- YARA performs syntactic pattern matching only; it cannot validate Base58Check checksums
  or perform elliptic curve operations
- YARA matches should be treated as candidates requiring secondary validation
- For full validation, pipe YARA hits into the Rust scanner for checksum and curve verification
- YARA's strength is fast pre-filtering of large memory dumps before expensive validation

---

## 9. Rust Implementation Strategy

### 9.1 Recommended Crate Dependencies

```toml
[dependencies]
# Base58 encoding/decoding
bs58 = "0.5"          # Base58 with check encoding

# Cryptographic primitives
sha2 = "0.10"         # SHA-256, SHA-512
tiny-keccak = "2.0"   # Keccak-256 (for Ethereum MAC verification)
hmac = "0.12"         # HMAC for PBKDF2
pbkdf2 = "0.12"       # PBKDF2 (for seed derivation)

# Elliptic curve operations
k256 = "0.13"         # secp256k1 (Bitcoin, Ethereum, Cosmos)
ed25519-dalek = "2"   # Ed25519 (Solana, Monero, Cardano, Polkadot)
curve25519-dalek = "4" # Low-level Curve25519 operations

# HD wallet derivation
bip32 = "0.5"         # BIP-32 HD key derivation

# Bech32 encoding
bech32 = "0.11"       # Bech32/Bech32m (Bitcoin SegWit, Cosmos, Cardano Shelley)

# Regex for pattern matching
regex = "1"            # Regex engine
aho-corasick = "1"    # Multi-pattern string matching (for BIP-39 words)
```

### 9.2 Scanner Architecture

```
MemoryDump
    |
    v
[String Extractor] -- extracts printable ASCII/UTF-8 strings
    |
    v
[Multi-Pattern Scanner] -- Aho-Corasick for BIP-39 words
    |                    -- Regex for WIF, xprv, addresses
    |                    -- Byte pattern for keystore JSON
    v
[Candidate Pool]
    |
    v
[Validator Pipeline]
    |-- Base58Check validator
    |-- Bech32 validator
    |-- BIP-39 checksum validator
    |-- Elliptic curve point validator
    |-- JSON structure validator
    |-- Cross-reference validator (pubkey <-> privkey)
    v
[Confirmed Findings]
    |
    v
[Reporter] -- categorized output with confidence levels
```

### 9.3 Performance Considerations

1. **Aho-Corasick for BIP-39:** Pre-build an Aho-Corasick automaton with all 2048 words.
   Single-pass scanning for all words simultaneously. O(n) where n = memory size.

2. **Lazy Validation:** Only perform expensive operations (EC point multiplication,
   SHA-256 double hash) on regex-matched candidates, not on raw memory.

3. **Parallel Scanning:** Memory chunks can be scanned in parallel using rayon.
   Each chunk should overlap by max-pattern-length bytes to avoid missing matches at boundaries.

4. **Memory Mapping:** Use `mmap` for large memory dumps to avoid loading entire file into RAM.

5. **Progressive Reporting:** Report findings as they're discovered, don't wait for full scan.

### 9.4 Confidence Levels

```rust
enum Confidence {
    /// Checksum-validated key with EC point verification
    Confirmed,
    /// Checksum-validated but no EC verification available
    High,
    /// Regex match with structural validation (JSON, length) but no checksum
    Medium,
    /// Regex match only; may be false positive
    Low,
}
```

### 9.5 Output Schema

```rust
struct CryptoKeyFinding {
    /// Type of key found
    key_type: KeyType,  // WIF, Xprv, Mnemonic, EthKeystore, SolanaKeypair, etc.
    /// Raw matched data
    raw_data: String,
    /// Offset in memory dump
    offset: u64,
    /// Length of matched data
    length: usize,
    /// Confidence level
    confidence: Confidence,
    /// Blockchain network
    network: Network,  // Bitcoin, Ethereum, Solana, Monero, etc.
    /// Derived public key/address (if computable)
    derived_address: Option<String>,
    /// Additional context (surrounding bytes, parent structure)
    context: String,
}
```

---

## References

### Specifications
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic Code for Generating Deterministic Keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-44: Multi-Account Hierarchy for Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [Web3 Secret Storage Definition (Ethereum Keystore)](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [XRP Ledger Cryptographic Keys](https://xrpl.org/docs/concepts/accounts/cryptographic-keys)
- [CIP-16: Cardano Cryptographic Key Serialisation Formats](https://cips.cardano.org/cip/CIP-16)
- [Monero Private Keys](https://docs.getmonero.org/cryptography/asymmetric/private-key/)
- [Bitcoin Wiki: Wallet Import Format](https://en.bitcoin.it/wiki/Wallet_import_format)
- [Bitcoin Wiki: Wallet Encryption](https://en.bitcoin.it/wiki/Wallet_encryption)
- [Bitcoin Wiki: Mini Private Key Format](https://en.bitcoin.it/wiki/Mini_private_key_format)

### Academic Research
- [Process Memory Investigation of Bitcoin Clients Electrum and Bitcoin Core (Van Der Horst et al. 2017)](https://www.researchgate.net/publication/320250953_Process_Memory_Investigation_of_the_Bitcoin_Clients_Electrum_and_Bitcoin_Core)
- [Memory FORESHADOW: Memory Forensics of Hardware Cryptocurrency Wallets (Thomas et al., DFRWS 2020)](https://www.sciencedirect.com/science/article/pii/S2666281720302511) -- [PDF via DFRWS](https://dfrws.org/wp-content/uploads/2020/10/2020_USA_paper-memory_foreshadow_memory_forensics_of_hardware_cryptocurrency_wallets_a_tool_and_visualization.pdf)
- [A Framework for Live Host-Based Bitcoin Wallet Forensics and Triage (2022)](https://www.sciencedirect.com/science/article/pii/S2666281722001676)
- [A Comprehensive Forensic Preservation Methodology for Crypto Wallets (2022)](https://www.sciencedirect.com/science/article/pii/S2666281722001585)
- [Forensic Investigation Framework for Cryptocurrency Wallet in the End Device (Park et al. 2023)](https://www.sciencedirect.com/science/article/abs/pii/S0167404823003024)
- [The Current State of Cryptocurrency Forensics -- Survey (2023)](https://www.sciencedirect.com/science/article/abs/pii/S2666281723000859)
- [Recovery CAT: A Digital Forensics Tool for Cryptocurrency Investigations (Hallman et al., IEEE 2024)](https://ieeexplore.ieee.org/document/10527279/) -- [PDF](https://www.researchgate.net/profile/Roger-Hallman/publication/378434568_Recovery_CAT_A_Digital_Forensics_Tool_for_Cryptocurrency_Investigations/links/67f183ba76d4923a1af7da1d/Recovery-CAT-A-Digital-Forensics-Tool-for-Cryptocurrency-Investigations.pdf)
- [Desktop Crypto Wallets: A Digital Forensic Investigation (SCITEPRESS 2024)](https://www.scitepress.org/Papers/2024/123130/123130.pdf)
- [Advanced Monero Wallet Forensics: MoeyEx (DFRWS 2025)](https://www.sciencedirect.com/science/article/pii/S2666281725001283)
- [Cryptocurrency Forensics Automation: Deep Learning and NLP-Based Approach (Springer 2025)](https://link.springer.com/article/10.1007/s10791-025-09595-1)
- [Recovery of Encryption Keys from Memory Using a Linear Scan (Halderman et al.)](https://www.researchgate.net/publication/221548532_Recovery_of_Encryption_Keys_from_Memory_Using_a_Linear_Scan)
- [Investigation of Cryptocurrency Wallets on iOS and Android (Montanez, Marshall University)](https://www.marshall.edu/forensics/files/Montanez-Angelica_Final-Research-Paper.pdf)

### Tools & Libraries
- [BTCRecover (GitHub)](https://github.com/gurnec/btcrecover)
- [CryKeX: Linux Memory Cryptographic Keys Extractor (GitHub)](https://github.com/cryptolok/CryKeX)
- [MetaMask Vault Decryptor](https://github.com/MetaMask/vault-decryptor)
- [metamask_pwn: Extract and Decrypt MetaMask Vaults (GitHub)](https://github.com/cyclone-github/metamask_pwn)
- [FEA: Forensics Enhanced Analysis for Autopsy (GitHub)](https://github.com/joaomotap/FEA)
- [Monero Address Regex (npm)](https://github.com/k4m4/monero-regex)
- [DFIR Regular Expressions (GitHub)](https://github.com/joshbrunty/DFIR-Regular-Expressions)
- [Solana Keypair Conversion Tools (GitHub)](https://github.com/codebasebo/Solana-Wallet-Key-Generation-and-Conversion-Tools)
- [crackBTCwallet: Crack Encrypted Master Key AES-256-CBC (GitHub)](https://github.com/albertobsd/crackBTCwallet)
- [bitcore-wallet-bdb2jsonl: Bitcoin Core BDB wallet.dat parser (GitHub)](https://github.com/bitpay/bitcore-wallet-bdb2jsonl)
- [kionactf/crypto-detection: YARA rules for crypto functions (GitHub)](https://github.com/kionactf/crypto-detection)
- [Manalyze bitcoin.yara: Bitcoin address YARA rule (GitHub)](https://github.com/JusticeRage/Manalyze/blob/master/bin/yara_rules/bitcoin.yara)
- [TRM Labs Seed Analysis](https://www.trmlabs.com/blockchain-intelligence-platform/forensics/seed-analysis)

### Wallet Documentation
- [MetaMask: How It Stores Your Wallet Secret](https://www.wispwisp.com/index.php/2020/12/25/how-metamask-stores-your-wallet-secret/)
- [Electrum Documentation: Version Bytes for Extended Keys](https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html)
- [Electrum Documentation: Seed Version System](https://electrum.readthedocs.io/en/latest/seedphrase.html)
- [Exodus Security](https://www.exodus.com/security)
- [Polkadot Cryptography](https://wiki.polkadot.com/learn/learn-cryptography/)
- [Solana Keypair Documentation](https://solana.com/developers/cookbook/wallets/create-keypair)
- [Bitcoin Core: Wallet Encryption (Bitcoin Core Academy)](https://bitcoincore.academy/wallet-encryption.html)
- [Bitcoin Core: Wallet Database (Bitcoin Core Academy)](https://bitcoincore.academy/wallet-database.html)
- [Bitcoin Core: CCrypter Class Reference (Doxygen)](https://doxygen.bitcoincore.org/classwallet_1_1_c_crypter.html)
- [Ethereum: Web3 Secret Storage Definition](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [Ethereum: eth-keyfile Reference Implementation (GitHub)](https://github.com/ethereum/eth-keyfile)
- [Monero Spend Key (Moneropedia)](https://www.getmonero.org/resources/moneropedia/spendkey.html)
- [Monero View Key (Moneropedia)](https://www.getmonero.org/resources/moneropedia/viewkey.html)
- [Cardano Key Pairs (Developer Portal)](https://developers.cardano.org/docs/operate-a-stake-pool/cardano-key-pairs/)
- [BIP-39 Wordlist Languages (SafeSeed)](https://safeseed.app/blog/bip39-word-list-all-languages/)

### Forensic Resources
- [Forensic Analysis of Digital Currencies in Investigations (Ankura)](https://angle.ankura.com/post/102hr1z/forensic-analysis-of-digital-currencies-in-investigations)
- [CyberCop Labs: RegEx Searching of Cryptocurrency Addresses](https://cybercoplabs.net/article/regex-searching-of-addresses/)
- [Demonic Vulnerability in MetaMask (SlowMist)](https://slowmist.medium.com/demonic-vulnerability-analysis-of-metamasks-wallet-browser-extension-8de529a70caf)
- [AESKeyFind: Memory Forensics for AES Key Recovery](https://www.siberoloji.com/aeskeyfind-kali-linux-advanced-memory-forensics-aes-key-recovery/)
- [Unlocking the Vault: Disk Image Forensic for MetaMask Passphrase Recovery (Medium)](https://medium.com/@0xVrka/unlocking-the-vault-disk-image-forensic-for-metamask-passphrase-recovery-via-master-passwords-8c44fcfd04ee)
- [Identifying Crypto Artifacts in the Field (TRM Labs Flip Book)](https://www.trmlabs.com/guides/identifying-crypto-artifacts-in-the-field-flip-book)
- [Bit-Flipping Attack on wallet.dat: AES-256-CBC Risks (Crypto Deep Tech)](https://cryptodeeptech.ru/bit-flipping-attack-on-wallet-dat/)
- [Bitcoin Core Source: src/key.h (GitHub)](https://github.com/bitcoin/bitcoin/blob/master/src/key.h)
- [Bitcoin Core Source: src/wallet/crypter.cpp (GitHub)](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/crypter.cpp)
- [BIP-39 Official Wordlists (GitHub)](https://github.com/bitcoin/bips/tree/master/bip-0039)
- [Learn Me A Bitcoin: WIF Private Key](https://learnmeabitcoin.com/technical/keys/private-key/wif/)
