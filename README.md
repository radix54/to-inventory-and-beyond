[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE.md)
[![Tests](https://github.com/radix54/to-inventory-and-beyond/actions/workflows/test.yml/badge.svg)](https://github.com/radix54/to-inventory-and-beyond/actions/workflows/test.yml)

# To Inventory and Beyond

Advanced Programming of Cryptographic Methods (APoCM) course laboratory project repository: EX_08_01 "*To Inventory and Beyond*".

> [!Warning]
> Do not use this code in real-world production implementations.

---

## Overview

`vaultshare` is a command-line tool designed for encrypted personal file storage and secure sharing among team members.
Each user generates a cryptographic identity consisting of a digital signing key pair and a key encapsulation / agreement key pair. Files stored in the vault are encrypted with symmetric keys derived from passwords via Argon2id. When sharing, a file's encryption key is encapsulated/wrapped for a specific recipient, and the packaged ciphertext is digitally signed by the sender.

---

## CBOM Analysis and Comparison

Two Software/Cryptography Bills of Materials (CBOMs) were generated for the initial Go codebase using:
1. **`cdxgen`** (`v13.7.0` with `--deep --type go --evidence --include-crypto`)
2. **`CBOMkit-hyperion`** (PQCA CBOMkit)

### Assets Comparison Matrix

| Cryptographic Asset | Location | `CBOMkit-hyperion` | `cdxgen` | Status & Vulnerabilities |
| :--- | :--- | :---: | :---: | :--- |
| **MD5** | `crypto.go:124, 166, 175` | **Yes** (lines 124, 166, 175) | **Partial** (line 124 only) | **Broken**: Used for file checksums and digital signature digests. Vulnerable to collision attacks and forgery. |
| **AES** | `crypto.go:86` | **Yes** (line 86) | **Yes** (line 86) | **Insecure Mode**: Both tools detect AES, but neither detects that it was operating in Electronic Codebook (**ECB**) mode with manual PKCS#7 padding (despite misleading comments claiming AES-GCM). |
| **RSA-2048** | `crypto.go:37` | **Yes** (line 37) | **Yes** (line 37 + PKCS#1 key components) | **Non-PQ & Legacy**: Vulnerable to Shor's algorithm on quantum computers; generated using a predictable PRNG (`math/rand`). |
| **SHA-256** | `crypto.go:69, 135` | **Partial** (line 69 only) | **Partial** (line 69 only) | Used in `Fingerprint` (acceptable) and line 135 as an informal/ad-hoc KDF for ECDH (missed by both tools). |
| **Argon2id** | `crypto.go:81` | **No** | **Yes** (via `golang.org/x/crypto`) | **Secure**: Memory-hard password hashing function, properly parameterized. |
| **ECDH (P-256)** | `crypto.go:41, 58, 130, 141` | **No** (Missed) | **No** (Missed) | **Non-PQ & Smell**: Completely missed by both scanners. Vulnerable to Shor's algorithm; lacks proper HKDF key expansion. |
| **PRNG (`math/rand`)** | `crypto.go:34` (`fastReader()`) | **No** (Missed) | **No** (Missed as asset) | **Critical Flaw**: Predictable pseudorandom generator seeded with Unix timestamp used for RSA key and salt generation. |

---

## Post-Quantum Cryptographic (PQC) Migration

To achieve quantum resistance and eliminate all cryptographic smells, the codebase underwent a total Post-Quantum Cryptography migration:

1. **Cryptographically Secure Randomness**:
   - Removed `fastReader()` and `math/rand` seeded by `time.Now().Unix()`.
   - Replaced all randomness sources with `crypto/rand.Reader` via `io.ReadFull(rand.Reader, ...)` for key, salt, and nonce generation.

2. **Digital Signatures (ML-DSA-65)**:
   - Replaced classical RSA-2048, MD5 digest, and PKCS#1 v1.5 padding with **ML-DSA-65** (NIST FIPS 204, Module-Lattice-Based Digital Signature Standard) using the standard library `crypto/mldsa`.
   - Maintained standard key serialization using `crypto/x509` with **PKCS#8** (`x509.MarshalPKCS8PrivateKey` / `x509.ParsePKCS8PrivateKey`) and **PKIX SubjectPublicKeyInfo** (`x509.MarshalPKIXPublicKey` / `x509.ParsePKIXPublicKey`).

3. **Key Encapsulation (ML-KEM-768)**:
   - Replaced classical ECDH P-256 and ad-hoc SHA-256 hashing with **ML-KEM-768** (NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism) using `crypto/mlkem`.
   - `WrapKey` encapsulates a 256-bit shared key and ciphertext via `ek.Encapsulate()`, then encrypts the target file key using AES-256-GCM.
   - `UnwrapKey` decapsulates the shared key via `dk.Decapsulate()` and decrypts the file key.

4. **Symmetric Encryption (AES-256-GCM)**:
   - Replaced raw block ECB mode and manual PKCS#7 padding with authenticated encryption using **AES-256-GCM** (`cipher.NewGCM`).
   - Every encryption operation generates a unique, cryptographically random 12-byte nonce prepended to the ciphertext, ensuring semantic security and ciphertext integrity.

5. **Integrity Checksums (SHA-256)**:
   - Replaced legacy MD5 hashing in `Checksum()` with collision-resistant **SHA-256** (`sha256.Sum256`).

6. **Variable and Struct Clean-Up**:
   - Replaced legacy algorithm names (`RSAPrivate` / `ECCPrivate` -> `SignPrivate` / `KEMPrivate`, `RSAPublic` / `ECCPublic` -> `SignPublic` / `KEMPublic`, `SenderRSA` -> `SenderSign`).
   - Retained original code commented out directly above each replacement in `crypto.go`, tagged with standardized metadata comments indicating CBOM detection and fixes.

---

## Build and Testing

### Prerequisites
- Go 1.27+ (required for standard library `crypto/mldsa`)
- Make

### Commands
```bash
# Build the application
make build

# Run all test suites
make test

# Launch the interactive CLI
make run

# Clean build artifacts
make clean

# Clean user/vault data
make clean-data
```

---

## Authors

**Group**: Deep Thought
- 267234 Marco Egidio Pusceddu (@MARCO5P)
- 267646 Lorenzo Radice (@ozneroL541)
## License

Copyright (C) 2026 Marco Egidio Pusceddu, Lorenzo Radice

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
