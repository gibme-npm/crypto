// Copyright (c) 2020-2025, Brandon Lehmann
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import Crypto, { crypto_bulletproof_plus_t, crypto_bulletproof_t, crypto_entropy_t, CryptoModule } from '../src';
import { deepEqual, equal, fail, notEqual, ok } from 'assert';
import { sha3_256 } from 'js-sha3';

/** @ignore */
export const env_is_set = (variable: any): boolean => {
    return variable === '1' || variable === 'true';
};

interface Vector {
    purpose?: number | string;
    coin_type?: number;
    account?: number;
    change?: number;
    address_index?: number;
    public_key: string;
    secret_key: string;
}

interface TestVector {
    seed: string;
    vectors: Vector[];
}

export const run_test = (describe: any, it: any, before: any) => {
    describe('Unit Tests', async () => {
        const crypto = await Crypto.init();

        if (env_is_set(process.env.FORCE_JS)) {
            if (!await Crypto.force_js_library()) {
                console.log('Could not activate Javascript Cryptographic Library');

                process.exit(1);
            }

            if (Crypto.library_type !== CryptoModule.Type.JS) {
                console.log('Could not activate Javascript Cryptographic Library');

                process.exit(1);
            }
        } else if (env_is_set(process.env.FORCE_WASM)) {
            if (!await Crypto.force_wasm_library()) {
                console.log('Could not activate WASM Cryptographic Library');

                process.exit(1);
            }

            if (Crypto.library_type !== CryptoModule.Type.WASM) {
                console.log('Could not activate WASM Cryptographic Library');

                process.exit(1);
            }
        }

        let languages: CryptoModule.Language[] = [];

        before(async () => {
            languages = await crypto.languages();
        });

        describe(`${crypto.library_name} Tests`, async () => {
            describe('Module Sanity', async () => {
                it('Library Type', async () => {
                    equal(Crypto.library_type, crypto.library_type);
                });

                it('Library Name', async () => {
                    equal(Crypto.library_name, crypto.library_name);
                });

                it('External Library', async () => {
                    crypto.external_library = {};
                    deepEqual(Crypto.external_library, crypto.external_library);
                });

                it('is_native', async () => {
                    equal(Crypto.is_native, crypto.is_native);

                    if (process.env.FORCE_JS || process.env.FORCE_WASM) {
                        notEqual(crypto.is_native, true);
                    } else {
                        equal(crypto.is_native, true);
                    }
                });

                it('languages', async () => {
                    const _languages = await crypto.languages();

                    deepEqual(_languages, languages);
                });
            });

            describe('Hashing', async () => {
                const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

                describe('Argon2', async () => {
                    it('Argon2d', async () => {
                        const result = await crypto.argon2d(INPUT_DATA, 4, 1024, 1);

                        equal(result, 'cd65323e3e56272fd19b745b0673318b21c2be5257f918267998b341719c3d5a');
                    });

                    it('Argon2i', async () => {
                        const result = await crypto.argon2i(INPUT_DATA, 4, 1024, 1);

                        equal(result, 'debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a');
                    });

                    it('Argon2id', async () => {
                        const result = await crypto.argon2id(INPUT_DATA, 4, 1024, 1);

                        equal(result, 'a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9');
                    });
                });

                describe('SHA3', async () => {
                    it('SHA256', async () => {
                        const result = await crypto.sha256(INPUT_DATA);

                        equal(result, '80ce2248b02f06777e4e53b9a0378474ddbc9d6a632c91476cc4e3e5176338f4');
                    });

                    it('SHA384', async () => {
                        const result = await crypto.sha384(INPUT_DATA);

                        equal(result, '6a337b0e4d296ca180fd536070eb89b071d24a472f29ba4001cf661b018cdce8');
                    });

                    it('SHA512', async () => {
                        const result = await crypto.sha512(INPUT_DATA);

                        equal(result, '14f7c0fcc89e2533e9f7ac184188538d4cf8d2f680338edc6449715d005d1696');
                    });

                    it('SHA3', async () => {
                        const result = await crypto.sha3(INPUT_DATA);

                        equal(result, '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb');
                    });

                    it('SHA3 Slow Hash [0]', async () => {
                        const result = await crypto.sha3_slow(INPUT_DATA);

                        equal(result, '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb');
                    });

                    it('SHA3 Slow Hash [4096]', async () => {
                        const result = await crypto.sha3_slow(INPUT_DATA, 4096);

                        equal(result, 'c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c');
                    });
                });

                describe('Other', async () => {
                    it('Blake2b', async () => {
                        const result = await crypto.blake2b(INPUT_DATA);

                        equal(result, '56a8ef7f9d7db21fa29b83eb77551f0c3e312525d6151946261911fc38a508c4');
                    });
                });

                describe('ED25519', async () => {
                    it('Hash to Point', async () => {
                        const result = await crypto.hash_to_point(INPUT_DATA);

                        ok(await crypto.check_point(result));
                        ok(!await crypto.check_scalar(result));
                    });

                    it('Hash to Scalar', async () => {
                        const result = await crypto.hash_to_scalar(INPUT_DATA);

                        ok(await crypto.check_scalar(result));
                        ok(!await crypto.check_point(result));
                    });
                });
            });

            describe('AES', async () => {
                const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';
                const PASSWORD = 'SuperSecretPassword';
                let encrypted: string;

                it('Encrypt', async () => {
                    encrypted = await crypto.aes_encrypt(INPUT_DATA, PASSWORD);

                    notEqual(encrypted, INPUT_DATA);
                });

                it('Decrypt', async () => {
                    const decrypted = await crypto.aes_decrypt(encrypted, PASSWORD);

                    equal(decrypted, INPUT_DATA);
                });
            });

            describe('Base58', async () => {
                const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

                it('Encode', async () => {
                    const encoded = await crypto.base58_encode(INPUT_DATA);

                    const decoded = await crypto.base58_decode(encoded);

                    equal(decoded.toString('hex'), INPUT_DATA);
                });

                it('Encode Fails', async () => {
                    const encoded = await crypto.base58_encode(INPUT_DATA);

                    try {
                        await crypto.base58_decode_check(encoded);

                        fail();
                    } catch {
                    }
                });

                it('Encode Check', async () => {
                    const encoded = await crypto.base58_encode_check(INPUT_DATA);

                    const decoded = await crypto.base58_decode_check(encoded);

                    equal(decoded.toString('hex'), INPUT_DATA);
                });

                it('Encode Check Fails', async () => {
                    const encoded = await crypto.base58_encode_check(INPUT_DATA);

                    try {
                        await crypto.base58_decode(encoded);

                        fail();
                    } catch {
                    }
                });
            });

            describe('CryptoNote Base58', async () => {
                const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

                it('Encode', async () => {
                    const encoded = await crypto.cn_base58_encode(INPUT_DATA);

                    const decoded = await crypto.cn_base58_decode(encoded);

                    equal(decoded.toString('hex'), INPUT_DATA);
                });

                it('Encode Fails', async () => {
                    const encoded = await crypto.cn_base58_encode(INPUT_DATA);

                    try {
                        await crypto.cn_base58_decode_check(encoded);

                        fail();
                    } catch {
                    }
                });

                it('Encode Check', async () => {
                    const encoded = await crypto.cn_base58_encode_check(INPUT_DATA);

                    const decoded = await crypto.cn_base58_decode_check(encoded);

                    equal(decoded.toString('hex'), INPUT_DATA);
                });

                it('Encode Check Fails', async () => {
                    const encoded = await crypto.cn_base58_encode_check(INPUT_DATA);

                    try {
                        await crypto.cn_base58_decode(encoded);

                        fail();
                    } catch {
                    }
                });
            });

            describe('Address Encoding', async () => {
                let public_spend: string, public_view: string;

                const prefix = 0x654b5;

                before(async () => {
                    const keys = await crypto.random_points(2);

                    public_spend = keys[0];

                    public_view = keys[1];
                });

                describe('Short', async () => {
                    it('Base58', async () => {
                        const encoded = await crypto.base58_address_encode(prefix, public_spend);

                        const result = await crypto.base58_address_decode(encoded);

                        equal(result.prefix, prefix);
                        equal(result.public_spend, public_spend);
                        notEqual(result.public_view, public_view);
                    });

                    it('CryptoNote Base58', async () => {
                        const encoded = await crypto.cn_base58_address_encode(prefix, public_spend);

                        const result = await crypto.cn_base58_address_decode(encoded);

                        equal(result.prefix, prefix);
                        equal(result.public_spend, public_spend);
                        notEqual(result.public_view, public_view);
                    });
                });

                describe('Long', async () => {
                    it('Base58', async () => {
                        const encoded = await crypto.base58_address_encode(prefix, public_spend, public_view);

                        const result = await crypto.base58_address_decode(encoded);

                        equal(result.prefix, prefix);
                        equal(result.public_spend, public_spend);
                        equal(result.public_view, public_view);
                    });

                    it('CryptoNote Base58', async () => {
                        const encoded = await crypto.cn_base58_address_encode(prefix, public_spend, public_view);

                        const result = await crypto.cn_base58_address_decode(encoded);

                        equal(result.prefix, prefix);
                        equal(result.public_spend, public_spend);
                        equal(result.public_view, public_view);
                    });
                });
            });

            describe('Mnemonics', async () => {
                let entropy: crypto_entropy_t;

                describe('12-word', async () => {
                    const hex = 'af3ec8ebe5ca135e8a569856ed3df29300000000000000000000000000000000';
                    const mnemonic_phrase = [
                        'quality', 'wagon', 'depend', 'slide',
                        'patrol', 'quantum', 'citizen', 'spread',
                        'finger', 'hazard', 'lake', 'cheap'].join(' ');

                    before(async () => {
                        entropy = await crypto.entropy_recover(mnemonic_phrase);
                    });

                    it('Encode', async function () {
                        const words = await crypto.mnemonics_encode(hex);

                        notEqual(words, entropy.mnemonic_phrase, 'phrase mismatch');

                        entropy = await crypto.entropy_recover(words);

                        equal(entropy.entropy, hex, 'hex mismatch');
                    });

                    it('Decode', async function () {
                        const result = await crypto.mnemonics_decode(entropy.mnemonic_phrase.split(' '));

                        equal(result.entropy, hex, 'hex mismatch');
                    });
                });

                describe('24-word', async () => {
                    const hex = 'd0d2a5bb06282da7b6e64b7ab53d30bfd72ad83d639d12f8e78f590d4bd42258';
                    const mnemonic_phrase = [
                        'speak', 'news', 'human', 'arrange',
                        'lizard', 'stable', 'swear', 'siren',
                        'kingdom', 'prepare', 'equip', 'leisure',
                        'increase', 'hire', 'void', 'inhale',
                        'base', 'shrimp', 'toilet', 'rare',
                        'start', 'tube', 'maximum', 'alien'].join(' ');

                    before(async () => {
                        entropy = await crypto.entropy_recover(mnemonic_phrase);
                    });

                    it('Encode', async function () {
                        const words = await crypto.mnemonics_encode(hex);

                        notEqual(words, entropy.mnemonic_phrase, 'phrase mismatch');

                        entropy = await crypto.entropy_recover(words);

                        equal(entropy.entropy, hex, 'hex mismatch');
                    });

                    it('Decode', async function () {
                        const result = await crypto.mnemonics_decode(entropy.mnemonic_phrase.split(' '));

                        equal(result.entropy, hex, 'hex mismatch');
                    });
                });
            });

            describe('Fundamentals', async () => {
                let m_entropy: any;
                let m_timestamp: number;
                let m_words: string[];

                it('Calculate Base2 Exponent', async () => {
                    for (let i = 0; i < 16; ++i) {
                        equal(await crypto.calculate_base2_exponent(1 << i), i);
                    }
                });

                it('Scalar Reduction', async () => {
                    let hash: string;

                    // sometimes, it's possible, that a hash could be a scalar already...
                    do {
                        hash = await crypto.random_hash();
                    } while (await crypto.check_scalar(hash));

                    ok(!await crypto.check_scalar(hash));

                    const result = await crypto.scalar_reduce(hash);

                    ok(await crypto.check_scalar(result));
                    notEqual(hash, result);
                });

                it('Check Scalar', async () => {
                    const value = 'bf356a444a9db6e5c396a36eb7207e2647c5f89db88b1e2218844bb54661910d';

                    ok(await crypto.check_scalar(value));
                    ok(!await crypto.check_point(value));
                });

                it('Check Point', async () => {
                    const value = '9f18b169834781952bdb781384147db67b1674a32103950c23491ad2ca850258';

                    ok(!await crypto.check_scalar(value));
                    ok(await crypto.check_point(value));
                });

                it('Random Scalar', async () => {
                    const scalar = await crypto.random_scalar();

                    ok(await crypto.check_scalar(scalar));
                });

                it('Random Point', async () => {
                    const point = await crypto.random_point();

                    ok(await crypto.check_point(point));
                });

                it('Random Hash', async () => {
                    notEqual(typeof await crypto.random_hash(), 'undefined');
                });

                it('Random Scalars', async () => {
                    const keys = await crypto.random_scalars(20);

                    const found: string[] = [];

                    for (const key of keys) {
                        if (found.indexOf(key) !== -1) {
                            fail();
                        }

                        found.push(key);
                    }
                });

                it('Random Points', async () => {
                    const keys = await crypto.random_points(20);

                    const found: string[] = [];

                    for (const key of keys) {
                        if (found.indexOf(key) !== -1) {
                            fail();
                        }

                        found.push(key);
                    }
                });

                it('Random Hashes', async () => {
                    const keys = await crypto.random_hashes(20);

                    const found: string[] = [];

                    for (const key of keys) {
                        if (found.indexOf(key) !== -1) {
                            fail();
                        }

                        found.push(key);
                    }
                });

                it('Generate Random Keys', async () => {
                    const {
                        public_key,
                        secret_key
                    } = await crypto.generate_keys();

                    ok(await crypto.check_point(public_key), `PK: ${public_key}`);
                    ok(await crypto.check_scalar(secret_key), `SK: ${secret_key}`);
                });

                it('Generate Sets of Random Keys', async () => {
                    const {
                        public_keys,
                        secret_keys
                    } = await crypto.generate_keys_m(10);

                    const test = async (pub: string, sec: string): Promise<boolean> => {
                        return await crypto.check_point(pub) &&
                            await crypto.check_scalar(sec) &&
                            await crypto.secret_key_to_public_key(sec) === pub;
                    };

                    const promises = [];

                    for (let i = 0; i < public_keys.length; ++i) {
                        promises.push(test(public_keys[i], secret_keys[i]));
                    }

                    ok(await Promise.all(promises));
                });

                it('Secret Key to Public Key', async () => {
                    const {
                        public_key,
                        secret_key
                    } = await crypto.generate_keys();

                    const public_key2 = await crypto.secret_key_to_public_key(secret_key);

                    equal(public_key, public_key2);
                });

                it('Private Key to Keys', async () => {
                    const {
                        public_key,
                        secret_key
                    } = await crypto.private_key_to_keys(
                        'd9576da853288ca0b690e4d8f37ef7b9f62883cb83e6ddaca4ad4a75897caa49');

                    equal(public_key, '900bc03f0692023f66251f3997476251c09a30f791a06c1a7c689355d37068f4');
                    equal(secret_key, 'b2f6930751533493bbeecbfaf4125dab77a31cee8f67cf64e94ba8251cacd10e');
                });

                it('Generate Seed', async () => {
                    const {
                        entropy,
                        timestamp,
                        mnemonic_phrase
                    } = await crypto.random_entropy();

                    const words = mnemonic_phrase.split(' ');

                    notEqual(timestamp, 0);
                    equal(entropy.length, 64);
                    notEqual(words.length, 0);

                    m_entropy = entropy;
                    m_words = words;
                    m_timestamp = timestamp;
                });

                it('Generate With Entropy', async () => {
                    const {
                        entropy,
                        timestamp,
                        mnemonic_phrase
                    } = await crypto.random_entropy(
                        (new Date()).toString());

                    const words = mnemonic_phrase.split(' ');

                    notEqual(timestamp, 0);
                    equal(entropy.length, 64);
                    notEqual(words.length, 0);

                    m_entropy = entropy;
                    m_words = words;
                    m_timestamp = timestamp;
                });

                it('Restore Seed', async () => {
                    const {
                        entropy,
                        timestamp
                    } = await crypto.entropy_recover(m_words);

                    equal(entropy, m_entropy);
                    equal(timestamp, m_timestamp);
                });
            });

            describe('Stealth Addresses', async () => {
                // generated ephemeral transaction key(s)
                const secret_key = '8aa074d10ef9098b1005d6c637d58c70ed42280f211ecdbedce636e397b1c50f';
                const public_key = 'acd356fee7e75963c3e5262eebbc3ebf5d99e629bbaf594ea1dfaf5ba20a8c64';
                // derived keys
                const derivation = '53015157e26fb069325d97f452e7dffc3f8230e09be8ff2fcc9784879d94c8ef';
                const derivation_scalar = '72c2917d8832ac375c968e45d4f32aef4d1c74a6d24e127d5811cfad4d47a008';
                // generated ephemerals
                const public_ephemeral = 'f132a196f22d010acbba5fef230d002b7b76d948fb02344ada1df819f41c515c';
                const secret_ephemeral = '890d5b355b4f9f6324581a4146b717b3e57b92c8d10e63775db9abaa4e252f09';
                // key images
                const key_image = '930f27ea3783aa27e20f9565940b8039d4c7c7c16b23264caed496a8924f9dc6';
                const key_image_2 = '57fe434fc2db114a591af80d381d4dce77723a57dacf3de6bed8da1c17d3bfcb';

                it('Generate Key Derivation', async () => {
                    const derv = await crypto.generate_derivation(public_key, secret_key);

                    equal(derv, derivation);
                });

                it('Generate Key Derivation Scalar', async () => {
                    const scalar = await crypto.generate_derivation_scalar(derivation, 2);

                    equal(scalar, derivation_scalar);
                });

                it('Derive Public Key', async () => {
                    const key = await crypto.derive_public_key(derivation_scalar, public_key);

                    equal(key, public_ephemeral);
                });

                it('Derive Secret Key', async () => {
                    const key = await crypto.derive_secret_key(derivation_scalar, secret_key);

                    equal(key, secret_ephemeral);
                });

                it('Underive Public Key', async () => {
                    const key = await crypto.underive_public_key(
                        derivation, public_ephemeral, 2);

                    equal(key, public_key);
                });

                it('Generate Key Image', async () => {
                    const key = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);

                    equal(key, key_image);
                });

                it('Generate Key Image v2', async () => {
                    const key = await crypto.generate_key_image_v2(secret_ephemeral);

                    equal(key, key_image_2);
                });
            });

            describe('Audit Methods', async () => {
                const key_count = 20;
                let public_keys: string[] = [];
                let secret_keys: string[] = [];
                let proof: string;

                before(async () => {
                    const result = await crypto.generate_keys_m(key_count);

                    public_keys = result.public_keys;
                    secret_keys = result.secret_keys;
                });

                it('Generate Outputs Proof', async () => {
                    proof = await crypto.generate_outputs_proof(secret_keys);

                    notEqual(proof.length, 0);

                    const key_images = await crypto.check_outputs_proof(public_keys, proof);

                    equal(key_images.length, key_count);
                });

                it('Check Outputs Proof', async () => {
                    const key_images = await crypto.check_outputs_proof(public_keys, proof);

                    equal(key_images.length, key_count);
                });

                it('Check Output Proof: Failure', async () => {
                    const keys = await crypto.random_points(20);

                    const key_images = await crypto.check_outputs_proof(keys, proof)
                        .catch(() => []);

                    equal(key_images.length, 0);
                });
            });

            describe('Hierarchical Deterministic Keys', async () => {
                describe('Simple Test', async () => {
                    const entropy = 'd3e2a5bb06b058269c4f39d3a0f1f6decef852d01bde2e0a1d0db6cdb7fe3203';
                    const expected_seed =
                        'e4d707a7d2badcddcc19021e6cb89a62b7f20d1912fb95ce60a2b95285037daa3afdf42f9536' +
                        'bcb957a26769ce79be46948cdb437c6c8439f3bdf9bf702172f1';
                    const expected_secret = '94daaef2d1fa54d19b907c0f2562df77394a380cceea7b531fb61cde1d03330d';
                    const expected_public = '753c5ea6ace1087ed2c34a9c69a448b4acfb6be25f0c95afbc89165c3c087208';

                    it('Generate BIP-39 Seed', async () => {
                        const seed = await crypto.generate_seed(entropy);

                        equal(seed, expected_seed, 'seed mismatch');
                    });

                    it('Check m/44\'/0\'/0\'/0\'/0\'', async () => {
                        const keys = await crypto.generate_child_key(expected_seed);

                        equal(keys.secret_key, expected_secret, 'secret mismatch');
                        equal(keys.public_key, expected_public, 'public mismatch');
                    });
                });

                describe('SLIP-0010 Test Vectors', async () => {
                    const test_vectors: TestVector[] = [
                        {
                            seed: '000102030405060708090a0b0c0d0e0f',
                            vectors: [
                                {
                                    public_key: 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed',
                                    secret_key: '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7'
                                },
                                {
                                    purpose: 0,
                                    public_key: '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c',
                                    secret_key: '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 1,
                                    public_key: '1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187',
                                    secret_key: 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 1,
                                    account: 2,
                                    public_key: 'ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1',
                                    secret_key: '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 1,
                                    account: 2,
                                    change: 2,
                                    public_key: '8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c',
                                    secret_key: '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 1,
                                    account: 2,
                                    change: 2,
                                    address_index: 1000000000,
                                    public_key: '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a',
                                    secret_key: '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793'
                                },
                                {
                                    purpose: 'm/0\'/1\'/2\'/2\'/1000000000\'',
                                    public_key: '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a',
                                    secret_key: '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793'
                                }
                            ]
                        },
                        {
                            // eslint-disable-next-line max-len
                            seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                            vectors: [
                                {
                                    public_key: '8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a',
                                    secret_key: '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012'
                                },
                                {
                                    purpose: 0,
                                    public_key: '86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037',
                                    secret_key: '1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 2147483647,
                                    public_key: '5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d',
                                    secret_key: 'ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 2147483647,
                                    account: 1,
                                    public_key: '2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45',
                                    secret_key: '3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 2147483647,
                                    account: 1,
                                    change: 2147483646,
                                    public_key: 'e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b',
                                    secret_key: '5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72'
                                },
                                {
                                    purpose: 0,
                                    coin_type: 2147483647,
                                    account: 1,
                                    change: 2147483646,
                                    address_index: 2,
                                    public_key: '47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0',
                                    secret_key: '551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d'
                                }
                            ]
                        }
                    ];

                    for (const test of test_vectors) {
                        describe(test.seed, async () => {
                            for (const vector of test.vectors) {
                                it(crypto.make_path(
                                    vector.purpose,
                                    vector.coin_type,
                                    vector.account,
                                    vector.change,
                                    vector.address_index
                                ), async () => {
                                    const keys = await crypto.generate_child_key(
                                        test.seed,
                                        vector.purpose,
                                        vector.coin_type,
                                        vector.account,
                                        vector.change,
                                        vector.address_index);

                                    equal(keys.private_key, vector.secret_key, 'secret mismatch');
                                    equal(keys.public_key, vector.public_key, 'public_key mismatch');
                                });
                            }
                        });
                    }
                });
            });

            describe('RFC8032 Signatures', async () => {
                let message: string, public_ephemeral: string, secret_ephemeral: string;

                before(async () => {
                    message = await crypto.random_scalar();
                    message += await crypto.random_point();

                    const random_keys = await crypto.generate_keys();

                    public_ephemeral = random_keys.public_key;
                    secret_ephemeral = random_keys.secret_key;
                });

                it('Generate Signature', async () => {
                    const signature = await crypto.generate_rfc8032_signature(message, secret_ephemeral);

                    const pass = await crypto.check_rfc8032_signature(message, public_ephemeral, signature);

                    ok(pass);
                });
            });

            describe('Signatures', async () => {
                let message_digest: string, public_ephemeral: string, secret_ephemeral: string;

                before(async () => {
                    message_digest = await crypto.random_hash();

                    const random_keys = await crypto.generate_keys();

                    public_ephemeral = random_keys.public_key;
                    secret_ephemeral = random_keys.secret_key;
                });

                it('Generate Signature', async () => {
                    const signature = await crypto.generate_signature(message_digest, secret_ephemeral);

                    const pass = await crypto.check_signature(message_digest, public_ephemeral, signature);

                    ok(pass);
                });

                it('Prepare Signature', async () => {
                    const signature = await crypto.prepare_signature(message_digest, public_ephemeral);

                    ok(!await crypto.check_signature(message_digest, public_ephemeral, signature));

                    const _signature = await crypto.complete_signature(secret_ephemeral, signature);

                    const pass = await crypto.check_signature(message_digest, public_ephemeral, _signature);

                    ok(pass);
                });
            });

            describe('Ring Signatures', async () => {
                let message_digest: string, public_ephemeral: string,
                    secret_ephemeral: string, key_image: string, public_keys: string[],
                    key_image2: string;

                // commitment info
                let input_blinding: string, input_commitment: string, public_commitments: string[],
                    pseudo_blinding: string, pseudo_commitment: string;

                const RING_SIZE = 8;
                const REAL_OUTPUT_INDEX = 3;

                before(async () => {
                    message_digest = await crypto.random_scalar();

                    const random_keys = await crypto.generate_keys();

                    public_ephemeral = random_keys.public_key;
                    secret_ephemeral = random_keys.secret_key;

                    key_image = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);

                    key_image2 = await crypto.generate_key_image_v2(secret_ephemeral);

                    public_keys = await crypto.random_points(RING_SIZE);

                    public_keys[REAL_OUTPUT_INDEX] = public_ephemeral;

                    input_blinding = await crypto.random_scalar();

                    input_commitment = await crypto.generate_pedersen_commitment(input_blinding, 100);

                    public_commitments = await crypto.random_points(RING_SIZE);

                    public_commitments[REAL_OUTPUT_INDEX] = input_commitment;

                    const {
                        blinding_factors,
                        commitments
                    } =
                        await crypto.generate_pseudo_commitments([100],
                            await crypto.random_scalars(1));

                    pseudo_blinding = blinding_factors[0];

                    pseudo_commitment = commitments[0];
                });

                describe('Borromean', async () => {
                    it('Generate Ring Signature', async () => {
                        const signature = await crypto.generate_borromean_signature(
                            message_digest,
                            secret_ephemeral,
                            public_keys);

                        const pass = await crypto.check_borromean_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            signature);

                        ok(pass);
                    });

                    it('Prepare Ring Signature', async () => {
                        const prepared = await crypto.prepare_borromean_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            REAL_OUTPUT_INDEX);

                        ok(!await crypto.check_borromean_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            prepared));

                        const signature = await crypto.complete_borromean_signature(
                            secret_ephemeral,
                            REAL_OUTPUT_INDEX,
                            prepared);

                        const pass = await crypto.check_borromean_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            signature);

                        ok(pass);
                    });
                });

                describe('CLSAG', async () => {
                    it('Generate Ring Signature', async () => {
                        const signature = await crypto.generate_clsag_signature(
                            message_digest,
                            secret_ephemeral,
                            public_keys);

                        const pass = await crypto.check_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            signature);

                        ok(pass);
                    });

                    it('Prepare Ring Signature', async () => {
                        const {
                            signature,
                            h,
                            mu_P
                        } = await crypto.prepare_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            REAL_OUTPUT_INDEX);

                        ok(!await crypto.check_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            signature));

                        const _signature = await crypto.complete_clsag_signature(
                            secret_ephemeral,
                            REAL_OUTPUT_INDEX,
                            signature,
                            h,
                            mu_P);

                        const pass = await crypto.check_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            _signature);

                        ok(pass);
                    });
                });

                describe('CLSAG with Commitments', async () => {
                    it('Generate Ring Signature', async () => {
                        const signature = await crypto.generate_clsag_signature(
                            message_digest,
                            secret_ephemeral,
                            public_keys,
                            input_blinding,
                            public_commitments,
                            pseudo_blinding,
                            pseudo_commitment);

                        const pass = await crypto.check_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            signature,
                            public_commitments);

                        ok(pass);
                    });

                    it('Prepare Ring Signature', async () => {
                        const {
                            signature,
                            h,
                            mu_P
                        } = await crypto.prepare_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            REAL_OUTPUT_INDEX,
                            input_blinding,
                            public_commitments,
                            pseudo_blinding,
                            pseudo_commitment);

                        ok(!await crypto.check_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            signature,
                            public_commitments));

                        const _signature = await crypto.complete_clsag_signature(
                            secret_ephemeral,
                            3,
                            signature,
                            h,
                            mu_P);

                        const pass = await crypto.check_clsag_signature(
                            message_digest,
                            key_image,
                            public_keys,
                            _signature,
                            public_commitments);

                        ok(pass);
                    });
                });

                describe('Triptych', async () => {
                    it('Generate Ring Signature', async () => {
                        const signature = await crypto.generate_triptych_signature(
                            message_digest,
                            secret_ephemeral,
                            public_keys,
                            input_blinding,
                            public_commitments,
                            pseudo_blinding,
                            pseudo_commitment);

                        const pass = await crypto.check_triptych_signature(
                            message_digest,
                            key_image2,
                            public_keys,
                            signature,
                            public_commitments);

                        ok(pass);
                    });

                    it('Prepare Ring Signature', async () => {
                        const {
                            signature,
                            xpow
                        } = await crypto.prepare_triptych_signature(
                            message_digest,
                            key_image2,
                            public_keys,
                            REAL_OUTPUT_INDEX,
                            input_blinding,
                            public_commitments,
                            pseudo_blinding,
                            pseudo_commitment);

                        ok(!await crypto.check_triptych_signature(
                            message_digest,
                            key_image2,
                            public_keys,
                            signature,
                            public_commitments));

                        const _signature = await crypto.complete_triptych_signature(
                            secret_ephemeral,
                            signature,
                            xpow);

                        const pass = await crypto.check_triptych_signature(
                            message_digest,
                            key_image2,
                            public_keys,
                            _signature,
                            public_commitments);

                        ok(pass);
                    });
                });
            });

            describe('RingCT', async () => {
                let blinding_factors: string[], C_1: string, C_2: string, C_fee: string, pseudo_commitments: string[];

                before(async () => {
                    blinding_factors = await crypto.random_scalars(2);
                });

                it('Generate Pedersen Commitment', async () => {
                    C_1 = await crypto.generate_pedersen_commitment(blinding_factors[0], 1500);

                    C_2 = await crypto.generate_pedersen_commitment(blinding_factors[1], 2000);

                    notEqual(C_1, C_2);
                });

                it('Generate Commitment Blinding Factor', async () => {
                    const derivation_scalar = await crypto.random_scalar();

                    const bf = await crypto.generate_commitment_blinding_factor(derivation_scalar);

                    notEqual(derivation_scalar, bf);
                });

                it('Generate Transaction Fee Commitment', async () => {
                    C_fee = await crypto.generate_transaction_fee_commitment(100);

                    notEqual(C_fee, C_1);
                    notEqual(C_fee, C_2);
                });

                it('Generate Pseudo Commitments', async () => {
                    const result = await crypto.generate_pseudo_commitments(
                        [3000, 600], blinding_factors);

                    pseudo_commitments = result.commitments;

                    equal(pseudo_commitments.length, 2);
                });

                it('Check Commitments Parity', async () => {
                    ok(await crypto.check_commitments_parity(pseudo_commitments, [C_1, C_2], 100));
                });

                it('Fail Check Commitments Parity', async () => {
                    ok(!await crypto.check_commitments_parity(pseudo_commitments, [C_1, C_2], 300));
                });

                it('Amount Masking', async () => {
                    const amount = 13371337;

                    const amount_mask = await crypto.generate_amount_mask(blinding_factors[0]);

                    const masked_amount = await crypto.toggle_masked_amount(amount_mask, amount);

                    const unmasked_amount = await crypto.toggle_masked_amount(amount_mask, masked_amount);

                    const amount_mask2 = await crypto.generate_amount_mask(blinding_factors[1]);

                    const unmasked_amount2 = await crypto.toggle_masked_amount(amount_mask2, masked_amount);

                    notEqual(masked_amount, unmasked_amount);
                    equal(Number(unmasked_amount), amount);
                    notEqual(unmasked_amount2, unmasked_amount);
                });
            });

            describe('Range Proofs', async () => {
                describe('Bulletproofs', async () => {
                    let proof: crypto_bulletproof_t, commitments: string[];

                    it('Prove', async () => {
                        const result = await crypto.generate_bulletproof(
                            [10000], await crypto.random_scalars(1));

                        proof = result.proof;
                        commitments = result.commitments;

                        ok(await crypto.check_bulletproof([proof], [commitments]));
                    });

                    it('Batched Verification', async () => {
                        const valid = await crypto.check_bulletproof(
                            [proof, proof], [commitments, commitments]);

                        ok(valid);
                    });

                    it('Big Batch Verification', async () => {
                        const valid = await crypto.check_bulletproof(
                            [proof, proof, proof, proof, proof, proof],
                            [commitments, commitments, commitments, commitments, commitments, commitments]);

                        ok(valid);
                    });

                    it('Fail Verification', async () => {
                        const fake_commitments = await crypto.random_points(1);

                        ok(!await crypto.check_bulletproof([proof], [fake_commitments]));
                    });
                });

                describe('Bulletproofs+', async () => {
                    let proof: crypto_bulletproof_plus_t, commitments: string[];

                    it('Prove', async () => {
                        const result = await crypto.generate_bulletproof_plus(
                            [10000], await crypto.random_scalars(1));

                        proof = result.proof;
                        commitments = result.commitments;

                        const pass = await crypto.check_bulletproof_plus([proof], [commitments]);

                        ok(pass === true);
                    });

                    it('Batched Verification', async () => {
                        const pass = await crypto.check_bulletproof_plus(
                            [proof, proof], [commitments, commitments]);

                        ok(pass === true);
                    });

                    it('Big Batch Verification', async () => {
                        const pass = await crypto.check_bulletproof_plus(
                            [proof, proof, proof, proof, proof, proof],
                            [commitments, commitments, commitments, commitments, commitments, commitments]);

                        ok(pass === true);
                    });

                    it('Fail Verification', async () => {
                        const fake_commitments = await crypto.random_points(1);

                        const pass = await crypto.check_bulletproof_plus([proof], [fake_commitments]);

                        ok(pass === false);
                    });
                });
            });

            describe('Check User Config', async () => {
                const sha3 = async (input: string): Promise<string> => {
                    try {
                        input = JSON.parse(input);
                        const hash = sha3_256(Buffer.from(input, Crypto.is_hex(input) ? 'hex' : undefined));

                        return Crypto.make_module_result(false, hash);
                    } catch (error: any) {
                        return Crypto.make_module_result(true, undefined, 'External call failure');
                    }
                };

                const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';
                const HASH = '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb';

                it('Test #1', async () => {
                    crypto.external_library.sha3 = sha3;

                    const result = await crypto.sha3(INPUT_DATA);

                    ok(result === HASH);
                });
            });
        });
    });
};
