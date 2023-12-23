# Standalone Cryptography Library

This repository a standalone cryptographic primitive wrapper library that can be included in various other projects in a variety of development environments, including:

* Node.js >= 12.x
* WASM
* Javascript asm.js

It wraps [https://github.com/gibme-c/crypto](https://github.com/gibme-c/crypto) and exposes much of the functionality of that package to the supported development environments.

**Note**: Due to the size of the resulting WASM/javascript module(s), only English mnemonic words are compiled by default.

### Features

* Core Structure Types
  * Primitive Structures
    * `crypto_seed_t`: 256-bit [Seed](https://wikipedia.org/wiki/Random_Seed)
      * Allows for the random generation of the seed with, or without, additional [entropy](https://wikipedia.org/wiki/Entropy_(computing))
      * Encodes the [unix time](https://wikipedia.org/wiki/Unix_time) the seed was created into the seed
      * Allows for the encoding and decoding of a seed to/from [Mnemonic](https://en.wikipedia.org/wiki/Mnemonic) words or phrases
      * Allows for the [deterministic](https://wikipedia.org/wiki/Deterministic_encryption) generation of:
        * A view key pair
        * `n` spend key pair(s)
    * `crypto_point_t`: [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) Elliptic Curve Point
    * `crypto_scalar_t`: [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) Elliptic Curve Scalar
  * Cryptographic Signature Types
    * `crypto_signature_t`: 512-bit [ED25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf) signature
    * `crypto_borromean_signature_t`: [Borromean](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) Ring Signature
    * `crypto_clsag_signature_t`: [CLSAG](https://eprint.iacr.org/2019/654.pdf) Ring Signature
    * `crypto_triptych_signature_t`: [Triptych](https://eprint.iacr.org/2020/018.pdf) Ring Signature
  * Proof Types
    * `crypto_bulletproof_t`: [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf)
    * `crypto_bulletproof_plus_t`: [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf)
* Core Functionality
  * [Stealth Addresses](https://bytecoin.org/old/whitepaper.pdf)
  * Auditing Methods
    * Prove & Verify output ownership with linking tags (key images)
  * [SHA3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) (256-bit)
    * Simple hashing via `sha3()`
    * Simple [key stretching](https://wikipedia.org/wiki/Key_stretching) via `sha3_slow()`
  * [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
    * Simple AES wrapper encrypting/decrypting data to/from hexadecimal encoded strings
  * [Argon2](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf) Hashing
    * Argon2d
    * Argon2i
    * Argon2id
  * Address Encoding with [Checksums](https://wikipedia.org/wiki/Checksum)
    * Dual-key (spend & view)
    * Single-key
    * Base58 or CryptoNote Base58 encoding
  * [Base58 Encoding](https://tools.ietf.org/html/draft-msporny-base58-02)
    * With or Without Checksum Calculations/Checks
    * **Note:** This implementation is **not** block-based and will not work with block-based Base58 encoding (ie. CryptoNote)
  * [CryptoNote Base58 Encoding](https://tools.ietf.org/html/draft-msporny-base58-02)
    * With or Without Checksum Calculations/Checks
    * **Note:** This implementation is block-based and will not work with non-block-based Base58 encoding
  * [Mnemonic](https://en.wikipedia.org/wiki/Mnemonic) Encoding
    * Utilizes SHA3 instead of CRC32 for checksum generation
    * Languages
      * [Chinese Simplified](https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_simplified.txt)
      * [Chinese Traditional](https://github.com/bitcoin/bips/blob/master/bip-0039/chinese_traditional.txt)
      * [Czech](https://github.com/bitcoin/bips/blob/master/bip-0039/czech.txt)
      * [English language](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
      * [French](https://github.com/bitcoin/bips/blob/master/bip-0039/french.txt)
      * [Italian](https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt)
      * [Japanese](https://github.com/bitcoin/bips/blob/master/bip-0039/japanese.txt)
      * [Korean](https://github.com/bitcoin/bips/blob/master/bip-0039/korean.txt)
      * [Portuguese](https://github.com/bitcoin/bips/blob/master/bip-0039/portuguese.txt)
      * [Spanish](https://github.com/bitcoin/bips/blob/master/bip-0039/spanish.txt)
* Signature Generation / Verification
  * [Message Signing](https://tools.ietf.org/html/rfc8032)
  * [Borromean](https://github.com/Blockstream/borromean_paper/raw/master/borromean_draft_0.01_34241bb.pdf) Ring Signatures
  * [CLSAG](https://eprint.iacr.org/2019/654.pdf) Ring Signatures
    * **Optional** use of pedersen commitment to zero proving
  * [Triptych](https://eprint.iacr.org/2020/018.pdf) Ring Signatures
    * **Requires** use of pedersen commitment to zero proving
* [Zero-knowledge proofs](https://wikipedia.org/Zero-knowledge-proof)
  * [RingCT](https://eprint.iacr.org/2015/1098.pdf)
    * [Pedersen Commitments](https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF)
    * Pseudo Commitments
    * Blinding Factors
    * Amount Masking
  * [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) Range Proofs
    * Variable bit length proofs (1 to 64 bits)
    * No limits to number of values proved or verified in a single call
    * Batch Verification
  * [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf) Range Proofs
    * Variable bit length proofs (1 to 64 bits)
    * No limits to number of values proved or verified in a single call
    * Batch Verification

## Javascript Library

**Note:** We build prebuilds of the Node.js native addon module as well as the WASM/JS binaries that are included for distribution with the NPM installed version of this package to speed up your development efforts.

If the prebuild for your system does not exist, it will compile the Node.js native addon module using CMake automatically.

### Dependencies

* [Node.js](https://nodejs.org) >= +16.x LTS (or Node v16)
* Compiler supporting C++17 (gcc/clang/etc)

### Node.js / Typescript / Javascript Installation

#### Yarn
```bash
yarn add @gibme/crypto
```

#### NPM
```bash
npm install @gibme/crypto
```

### Initialization

#### TypeScript

```javascript
import Crypto from '@gibme/crypto';

(async() => {
    const crypto = await Crypto.init();
})
```

#### CommonJS

```javascript
const Crypto = require('@gibme/crypto').default

(async() => {
    const crypto = await Crypto.init();
})
```

#### Documentation

You can find the full TypeScript/JS documentation for this library [here](https://gibme-npm.github.io/crypto/).

## License

External references are provided via libraries in the Public Domain (Unlicense), MIT, and/or BSD from their respective parties.

This wrapper library is provided under the BSD-3-Clause license found in the LICENSE file.

Please make sure when using this library that you follow the licensing requirements set forth in all licenses.
