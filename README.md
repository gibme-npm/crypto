# Standalone Cryptography Library

A standalone cryptographic primitive wrapper library that can be included in various projects across a variety of development environments, including:

* Node.js >= 22.x (native C++ addon)
* WASM
* Javascript (asm.js)

It wraps [gibme-c/crypto](https://github.com/gibme-c/crypto) and exposes much of the functionality of that package to the supported development environments.

**Note**: Due to the size of the resulting WASM/Javascript module(s), only English mnemonic words are compiled by default.

**Note**: If you are looking to use this package in a browser, please read the [browser directions](#browser-usage--installation) below for a lighter installation path and minimal package size.

## Features

* Hashing (Argon2d/i/id, SHA-256, Keccak, Blake2b, and more)
* Key derivation and HD keys (BIP32/BIP44/SLIP-0010)
* Mnemonic seed generation and restoration
* Digital signatures (Ed25519, ring signatures, CLSAG, Triptych)
* Range proofs (Bulletproofs, Bulletproofs+)
* RingCT (Pedersen commitments, pseudo commitments, amount masking)
* Multisig support
* Automatic module selection: native C++ addon > WASM > asm.js fallback

## Node.js Library

Prebuilds of the Node.js native addon module and WASM/JS binaries are included with the npm-distributed package. If a prebuild for your platform does not exist, the native addon will be compiled automatically via CMake.

### Dependencies

* [Node.js](https://nodejs.org) >= 22.x
* Compiler supporting C++17 (gcc/clang/MSVC)

### Installation

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

```typescript
import Crypto from '@gibme/crypto';

const crypto = await Crypto.init();
```

#### CommonJS

```javascript
const Crypto = require('@gibme/crypto').default;

const crypto = await Crypto.init();
```

### Forcing a Specific Module

By default, the library selects the best available module (native > WASM > JS). You can override this:

```typescript
import Crypto from '@gibme/crypto';

const crypto = await Crypto.init();

// Force WASM module
await Crypto.force_wasm_library();

// Force JS (asm.js) module
await Crypto.force_js_library();
```

### Subpath Exports

The package provides subpath exports for directly importing specific module loaders:

```typescript
import Crypto from '@gibme/crypto/wasm'; // WASM loader
import Crypto from '@gibme/crypto/asm';  // asm.js loader
import Crypto from '@gibme/crypto/node'; // Native addon loader
```

## Browser Usage / Installation

For browser environments, use the dedicated browser package which provides a lighter installation without the native C++ addon.

#### Yarn

```bash
yarn add @gibme/crypto-browser
```

#### NPM

```bash
npm install @gibme/crypto-browser
```

### Initialization

#### TypeScript

```typescript
import Crypto from '@gibme/crypto-browser';

const crypto = await Crypto.init();
```

#### CommonJS

```javascript
const Crypto = require('@gibme/crypto-browser').default;

const crypto = await Crypto.init();
```

## Documentation

Full TypeScript/JS API documentation is available at [gibme-npm.github.io/crypto](https://gibme-npm.github.io/crypto/).

## License

External references are provided via libraries in the Public Domain (Unlicense), MIT, and/or BSD from their respective parties.

This wrapper library is provided under the BSD-3-Clause license found in the LICENSE file.

Please make sure when using this library that you follow the licensing requirements set forth in all licenses.
