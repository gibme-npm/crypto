# Standalone Cryptography Library

This repository a standalone cryptographic primitive wrapper library that can be included in various other projects in a variety of development environments, including:

* Node.js >= 18.x
* WASM
* Javascript asm.js

It wraps [https://github.com/gibme-c/crypto](https://github.com/gibme-c/crypto) and exposes much of the functionality of that package to the supported development environments.

**Note**: Due to the size of the resulting WASM/javascript module(s), only English mnemonic words are compiled by default.

**Note**: If you are looking to use this package in a browser, please read the browser directions below for a lighter installation path/method and a minimal package size.

## Javascript Library

**Note:** We build prebuilds of the Node.js native addon module as well as the WASM/JS binaries that are included for distribution with the NPM installed version of this package to speed up your development efforts.

If the prebuild for your system does not exist, it will compile the Node.js native addon module using CMake automatically.

### Dependencies

* [Node.js](https://nodejs.org) >= +16.x LTS (or Node v16)
* Compiler supporting C++17 (gcc/clang/etc)

### Node.js Installation

#### Yarn
```bash
yarn add @gibme/crypto
```

#### NPM
```bash
npm install @gibme/crypto
```

#### Initialization

##### TypeScript

```javascript
import Crypto from '@gibme/crypto';

(async() => {
    const crypto = await Crypto.init();
})
```

##### CommonJS

```javascript
const Crypto = require('@gibme/crypto').default

(async() => {
    const crypto = await Crypto.init();
})
```

### Browser Usage / Installation

#### Yarn

```bash
yarn add @gibme/crypto-browser
```

#### NPM

```bash
npm install @gibme/crypto-browser
```

#### Initialization

##### TypeScript

```javascript
import Crypto from '@gibme/crypto-browser';

(async() => {
    const crypto = await Crypto.init();
})
```

##### CommonJS

```javascript
const Crypto = require('@gibme/crypto-browser').default

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
