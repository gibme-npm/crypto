// Copyright (c) 2020-2023, Brandon Lehmann
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

import Crypto, {
    crypto_bulletproof_plus_t,
    crypto_bulletproof_t,
    make_module_result,
    is_hex
} from '../typescript';
import { describe, it, before } from 'mocha';
import assert from 'assert';
import { sha3_256 } from 'js-sha3';
import test_language from './mnemonics';

/** @ignore */
const env_is_set = (variable: any): boolean => {
    return variable === '1' || variable === 'true';
};

(async () => {
    const crypto = await Crypto.init();

    if (env_is_set(process.env.FORCE_JS)) {
        if (!await Crypto.force_js_library()) {
            console.error('Could not activate Javascript Cryptographic Library');

            process.exit(1);
        }
    } else if (env_is_set(process.env.FORCE_WASM)) {
        if (!await Crypto.force_wasm_library()) {
            console.error('Could not activate WASM Cryptographic Library');

            process.exit(1);
        }
    }

    const languages = await crypto.languages();

    describe(`${crypto.library_name} Tests`, async () => {
        let wallet_seed: string;

        before(async () => {
            wallet_seed = await crypto.random_hash();
        });

        describe('Module Sanity', async () => {
            it('Library Type', async () => {
                assert.equal(Crypto.library_type, crypto.library_type);
            });

            it('Library Name', async () => {
                assert.equal(Crypto.library_name, crypto.library_name);
            });

            it('External Library', async () => {
                crypto.external_library = {};
                assert.deepEqual(Crypto.external_library, crypto.external_library);
            });

            it('is_native', async () => {
                assert.equal(Crypto.is_native, crypto.is_native);

                if (process.env.FORCE_JS || process.env.FORCE_WASM) {
                    assert.notEqual(crypto.is_native, true);
                } else {
                    assert.equal(crypto.is_native, true);
                }
            });

            it('languages', async () => {
                const _languages = await crypto.languages();

                assert.deepEqual(_languages, languages);
            });
        });

        describe('Hashing', async () => {
            const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

            it('Argon2d', async () => {
                const result = await crypto.argon2d(INPUT_DATA, 4, 1024, 1);

                assert.equal(result, 'cd65323e3e56272fd19b745b0673318b21c2be5257f918267998b341719c3d5a');
            });

            it('Argon2i', async () => {
                const result = await crypto.argon2i(INPUT_DATA, 4, 1024, 1);

                assert.equal(result, 'debb2a3b51732bff26670753c5dbaedf6139c177108fe8e0744305c8d410a75a');
            });

            it('Argon2id', async () => {
                const result = await crypto.argon2id(INPUT_DATA, 4, 1024, 1);

                assert.equal(result, 'a6ac954bce48a46bc01a9b16b484ffb745401ae421b1b6f2e22cf474d4cac1c9');
            });

            it('SHA3', async () => {
                const result = await crypto.sha3(INPUT_DATA);

                assert.equal(result, '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb');
            });

            it('SHA3 Slow Hash [0]', async () => {
                const result = await crypto.sha3_slow(INPUT_DATA);

                assert.equal(result, '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb');
            });

            it('SHA3 Slow Hash [4096]', async () => {
                const result = await crypto.sha3_slow(INPUT_DATA, 4096);

                assert.equal(result, 'c031be420e429992443c33c2a453287e2678e70b8bce95dfe7357bcbf36ca86c');
            });

            it('Hash to Point', async () => {
                const result = await crypto.hash_to_point(INPUT_DATA);

                assert.ok(await crypto.check_point(result));
                assert.ok(!await crypto.check_scalar(result));
            });

            it('Hash to Scalar', async () => {
                const result = await crypto.hash_to_scalar(INPUT_DATA);

                assert.ok(await crypto.check_scalar(result));
                assert.ok(!await crypto.check_point(result));
            });
        });

        describe('AES', async () => {
            const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';
            const PASSWORD = 'SuperSecretPassword';
            let encrypted: string;

            it('Encrypt', async () => {
                encrypted = await crypto.aes_encrypt(INPUT_DATA, PASSWORD);

                assert.notEqual(encrypted, INPUT_DATA);
            });

            it('Decrypt', async () => {
                const decrypted = await crypto.aes_decrypt(encrypted, PASSWORD);

                assert.equal(decrypted, INPUT_DATA);
            });
        });

        describe('Base58', async () => {
            const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

            it('Encode', async () => {
                const encoded = await crypto.base58_encode(INPUT_DATA);

                const decoded = await crypto.base58_decode(encoded);

                assert.equal(decoded.toString('hex'), INPUT_DATA);
            });

            it('Encode Fails', async () => {
                const encoded = await crypto.base58_encode(INPUT_DATA);

                try {
                    await crypto.base58_decode_check(encoded);

                    assert.fail();
                } catch {}
            });

            it('Encode Check', async () => {
                const encoded = await crypto.base58_encode_check(INPUT_DATA);

                const decoded = await crypto.base58_decode_check(encoded);

                assert.equal(decoded.toString('hex'), INPUT_DATA);
            });

            it('Encode Check Fails', async () => {
                const encoded = await crypto.base58_encode_check(INPUT_DATA);

                try {
                    await crypto.base58_decode(encoded);

                    assert.fail();
                } catch {}
            });
        });

        describe('CryptoNote Base58', async () => {
            const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';

            it('Encode', async () => {
                const encoded = await crypto.cn_base58_encode(INPUT_DATA);

                const decoded = await crypto.cn_base58_decode(encoded);

                assert.equal(decoded.toString('hex'), INPUT_DATA);
            });

            it('Encode Fails', async () => {
                const encoded = await crypto.cn_base58_encode(INPUT_DATA);

                try {
                    await crypto.cn_base58_decode_check(encoded);

                    assert.fail();
                } catch {}
            });

            it('Encode Check', async () => {
                const encoded = await crypto.cn_base58_encode_check(INPUT_DATA);

                const decoded = await crypto.cn_base58_decode_check(encoded);

                assert.equal(decoded.toString('hex'), INPUT_DATA);
            });

            it('Encode Check Fails', async () => {
                const encoded = await crypto.cn_base58_encode_check(INPUT_DATA);

                try {
                    await crypto.cn_base58_decode(encoded);

                    assert.fail();
                } catch {}
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

                    assert.equal(result.prefix, prefix);
                    assert.equal(result.public_spend, public_spend);
                    assert.notEqual(result.public_view, public_view);
                });

                it('CryptoNote Base58', async () => {
                    const encoded = await crypto.cn_base58_address_encode(prefix, public_spend);

                    const result = await crypto.cn_base58_address_decode(encoded);

                    assert.equal(result.prefix, prefix);
                    assert.equal(result.public_spend, public_spend);
                    assert.notEqual(result.public_view, public_view);
                });
            });

            describe('Long', async () => {
                it('Base58', async () => {
                    const encoded = await crypto.base58_address_encode(prefix, public_spend, public_view);

                    const result = await crypto.base58_address_decode(encoded);

                    assert.equal(result.prefix, prefix);
                    assert.equal(result.public_spend, public_spend);
                    assert.equal(result.public_view, public_view);
                });

                it('CryptoNote Base58', async () => {
                    const encoded = await crypto.cn_base58_address_encode(prefix, public_spend, public_view);

                    const result = await crypto.cn_base58_address_decode(encoded);

                    assert.equal(result.prefix, prefix);
                    assert.equal(result.public_spend, public_spend);
                    assert.equal(result.public_view, public_view);
                });
            });
        });

        describe('Mnemonics', async () => {
            for (const language of languages) {
                test_language(crypto, language);
            }
        });

        describe('Fundamentals', async () => {
            let m_seed: any;
            let m_timestamp: number;
            let m_words: string[];

            it('Calculate Base2 Exponent', async () => {
                for (let i = 0; i < 16; ++i) {
                    assert.equal(await crypto.calculate_base2_exponent(1 << i), i);
                }
            });

            it('Scalar Reduction', async () => {
                let hash: string;

                // sometimes, it's possible, that a hash could be a scalar already...
                do {
                    hash = await crypto.random_hash();
                } while (await crypto.check_scalar(hash));

                assert.ok(!await crypto.check_scalar(hash));

                const result = await crypto.scalar_reduce(hash);

                assert.ok(await crypto.check_scalar(result));
                assert.notEqual(hash, result);
            });

            it('Check Scalar', async () => {
                const value = 'bf356a444a9db6e5c396a36eb7207e2647c5f89db88b1e2218844bb54661910d';

                assert.ok(await crypto.check_scalar(value));
                assert.ok(!await crypto.check_point(value));
            });

            it('Check Point', async () => {
                const value = '9f18b169834781952bdb781384147db67b1674a32103950c23491ad2ca850258';

                assert.ok(!await crypto.check_scalar(value));
                assert.ok(await crypto.check_point(value));
            });

            it('Random Scalar', async () => {
                const scalar = await crypto.random_scalar();

                assert.ok(await crypto.check_scalar(scalar));
            });

            it('Random Point', async () => {
                const point = await crypto.random_point();

                assert.ok(await crypto.check_point(point));
            });

            it('Random Hash', async () => {
                assert.notEqual(typeof await crypto.random_hash(), 'undefined');
            });

            it('Random Scalars', async () => {
                const keys = await crypto.random_scalars(20);

                const found: string[] = [];

                for (const key of keys) {
                    if (found.indexOf(key) !== -1) {
                        assert.fail();
                    }

                    found.push(key);
                }
            });

            it('Random Points', async () => {
                const keys = await crypto.random_points(20);

                const found: string[] = [];

                for (const key of keys) {
                    if (found.indexOf(key) !== -1) {
                        assert.fail();
                    }

                    found.push(key);
                }
            });

            it('Random Hashes', async () => {
                const keys = await crypto.random_hashes(20);

                const found: string[] = [];

                for (const key of keys) {
                    if (found.indexOf(key) !== -1) {
                        assert.fail();
                    }

                    found.push(key);
                }
            });

            it('Generate Random Keys', async () => {
                const { public_key, secret_key } = await crypto.generate_keys();

                assert.ok(await crypto.check_point(public_key));
                assert.ok(await crypto.check_scalar(secret_key));
            });

            it('Generate Sets of Random Keys', async () => {
                const { public_keys, secret_keys } = await crypto.generate_keys_m(10);

                const test = async (pub: string, sec: string): Promise<boolean> => {
                    return await crypto.check_point(pub) &&
                        await crypto.check_scalar(sec) &&
                        await crypto.secret_key_to_public_key(sec) === pub;
                };

                const promises = [];

                for (let i = 0; i < public_keys.length; ++i) {
                    promises.push(test(public_keys[i], secret_keys[i]));
                }

                assert.ok(await Promise.all(promises));
            });

            it('Secret Key to Public Key', async () => {
                const { public_key, secret_key } = await crypto.generate_keys();

                const public_key2 = await crypto.secret_key_to_public_key(secret_key);

                assert.equal(public_key, public_key2);
            });

            it('Generate Seed', async () => {
                const { seed, timestamp, mnemonic_phrase } = await crypto.random_seed();

                const words = mnemonic_phrase.split(' ');

                assert.notEqual(timestamp, 0);
                assert.equal(seed.length, 64);
                assert.notEqual(words.length, 0);

                m_seed = seed;
                m_words = words;
                m_timestamp = timestamp;
            });

            it('Generate With Entropy', async () => {
                const { seed, timestamp, mnemonic_phrase } = await crypto.random_seed(
                    (new Date()).toString());

                const words = mnemonic_phrase.split(' ');

                assert.notEqual(timestamp, 0);
                assert.equal(seed.length, 64);
                assert.notEqual(words.length, 0);

                m_seed = seed;
                m_words = words;
                m_timestamp = timestamp;
            });

            it('Restore Seed', async () => {
                const { seed, timestamp } = await crypto.seed_recover(m_words);

                assert.equal(seed, m_seed);
                assert.equal(timestamp, m_timestamp);
            });

            it('Generate Spend Keys From Seed', async () => {
                const { secret_key } = await crypto.seed_spend_keys(wallet_seed);

                assert.notEqual(secret_key, wallet_seed);
            });

            it('Generate View Keys From Seed', async () => {
                const spend = await crypto.seed_spend_keys(wallet_seed);

                const view = await crypto.seed_view_keys(wallet_seed);

                assert.notEqual(spend.public_key, view.public_key);
                assert.notEqual(spend.secret_key, view.secret_key);
                assert.notEqual(spend.public_key, view.secret_key);
                assert.notEqual(spend.secret_key, view.public_key);
            });
        });

        describe('Stealth Addresses', async () => {
            const public_key = 'f572a598c02f19b81e205f31cbb23bbc4997a8e8cd5aacd1c6f11b50b0760a2d';
            const secret_key = '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909';
            const derivation = '765e9a3ad29efabb9d749e87ac817ce4d1e105600b7e5fd0e335ee87bc1f08aa';
            const derivation_scalar = 'a43941b596eaacc54c469fd53ad20175efdf6aa366fd61dfb4534337b68ae909';
            const public_ephemeral = '8692c8d93cc07d2ce9126fed65214a86129383b464598bfa57b1368b91d875f6';
            const secret_ephemeral = '20ceeb1074cc86b9029406f48079d71d06060d8a5a1cfb7e3f2fef897a6a9303';
            const key_image = '62384706087b9dc3d77e510725478678c4c2350feff5117eb3e55436b7c2c128';
            const key_image_2 = '83451e45ea1531430a94a94dfe69515ec1111d69ec9cee8d5751bfc84450314a';

            it('Generate Key Derivation', async () => {
                const derv = await crypto.generate_derivation(public_key, secret_key);

                assert.equal(derivation, derv);
            });

            it('Generate Key Derivation Scalar', async () => {
                const scalar = await crypto.generate_derivation_scalar(derivation, 2);

                assert.equal(derivation_scalar, scalar);
            });

            it('Derive Public Key', async () => {
                const key = await crypto.derive_public_key(derivation_scalar, public_key);

                assert.equal(public_ephemeral, key);
            });

            it('Derive Secret Key', async () => {
                const key = await crypto.derive_secret_key(derivation_scalar, secret_key);

                assert.equal(secret_ephemeral, key);
            });

            it('Underive Public Key', async () => {
                const key = await crypto.underive_public_key(
                    derivation, public_ephemeral, 2);

                assert.equal(public_key, key);
            });

            it('Generate Key Image', async () => {
                const key = await crypto.generate_key_image(public_ephemeral, secret_ephemeral);

                assert.equal(key_image, key);
            });

            it('Generate Key Image v2', async () => {
                const key = await crypto.generate_key_image_v2(secret_ephemeral);

                assert.equal(key_image_2, key);
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

                assert.notEqual(proof.length, 0);

                const key_images = await crypto.check_outputs_proof(public_keys, proof);

                assert.equal(key_images.length, key_count);
            });

            it('Check Outputs Proof', async () => {
                const key_images = await crypto.check_outputs_proof(public_keys, proof);

                assert.equal(key_images.length, key_count);
            });

            it('Check Output Proof: Failure', async () => {
                const keys = await crypto.random_points(20);

                const key_images = await crypto.check_outputs_proof(keys, proof)
                    .catch(() => []);

                assert.equal(key_images.length, 0);
            });
        });

        describe('Deterministic Subwallets', async () => {
            const wallet_seed = '7c6e07d6ec21f16431331dce52c3ff90aeb97d5e46dc18422e6fe2d456add603';

            it('Generate Subwallet #0', async () => {
                const { secret_key } = await crypto.seed_spend_keys(wallet_seed, 0);

                assert.notEqual(secret_key, wallet_seed);
            });

            it('Generate Subwallet #999', async () => {
                const { secret_key } = await crypto.seed_spend_keys(wallet_seed, 999);

                assert.notEqual(secret_key, wallet_seed);
            });

            it('Generate Subwallet #512000', async () => {
                const { secret_key } = await crypto.seed_spend_keys(wallet_seed, 512000);

                assert.notEqual(secret_key, wallet_seed);
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

                assert.ok(pass);
            });

            it('Prepare Signature', async () => {
                const signature = await crypto.prepare_signature(message_digest, public_ephemeral);

                assert.ok(!await crypto.check_signature(message_digest, public_ephemeral, signature));

                const _signature = await crypto.complete_signature(secret_ephemeral, signature);

                const pass = await crypto.check_signature(message_digest, public_ephemeral, _signature);

                assert.ok(pass);
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

                const { blinding_factors, commitments } =
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

                    assert.ok(pass);
                });

                it('Prepare Ring Signature', async () => {
                    const prepared = await crypto.prepare_borromean_signature(
                        message_digest,
                        key_image,
                        public_keys,
                        REAL_OUTPUT_INDEX);

                    assert.ok(!await crypto.check_borromean_signature(
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

                    assert.ok(pass);
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

                    assert.ok(pass);
                });

                it('Prepare Ring Signature', async () => {
                    const { signature, h, mu_P } = await crypto.prepare_clsag_signature(
                        message_digest,
                        key_image,
                        public_keys,
                        REAL_OUTPUT_INDEX);

                    assert.ok(!await crypto.check_clsag_signature(
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

                    assert.ok(pass);
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

                    assert.ok(pass);
                });

                it('Prepare Ring Signature', async () => {
                    const { signature, h, mu_P } = await crypto.prepare_clsag_signature(
                        message_digest,
                        key_image,
                        public_keys,
                        REAL_OUTPUT_INDEX,
                        input_blinding,
                        public_commitments,
                        pseudo_blinding,
                        pseudo_commitment);

                    assert.ok(!await crypto.check_clsag_signature(
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

                    assert.ok(pass);
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

                    assert.ok(pass);
                });

                it('Prepare Ring Signature', async () => {
                    const { signature, xpow } = await crypto.prepare_triptych_signature(
                        message_digest,
                        key_image2,
                        public_keys,
                        REAL_OUTPUT_INDEX,
                        input_blinding,
                        public_commitments,
                        pseudo_blinding,
                        pseudo_commitment);

                    assert.ok(!await crypto.check_triptych_signature(
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

                    assert.ok(pass);
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

                assert.notEqual(C_1, C_2);
            });

            it('Generate Commitment Blinding Factor', async () => {
                const derivation_scalar = await crypto.random_scalar();

                const bf = await crypto.generate_commitment_blinding_factor(derivation_scalar);

                assert.notEqual(derivation_scalar, bf);
            });

            it('Generate Transaction Fee Commitment', async () => {
                C_fee = await crypto.generate_transaction_fee_commitment(100);

                assert.notEqual(C_fee, C_1);
                assert.notEqual(C_fee, C_2);
            });

            it('Generate Pseudo Commitments', async () => {
                const result = await crypto.generate_pseudo_commitments(
                    [3000, 600], blinding_factors);

                pseudo_commitments = result.commitments;

                assert.equal(pseudo_commitments.length, 2);
            });

            it('Check Commitments Parity', async () => {
                assert.ok(await crypto.check_commitments_parity(pseudo_commitments, [C_1, C_2], 100));
            });

            it('Fail Check Commitments Parity', async () => {
                assert.ok(!await crypto.check_commitments_parity(pseudo_commitments, [C_1, C_2], 300));
            });

            it('Amount Masking', async () => {
                const amount = 13371337;

                const amount_mask = await crypto.generate_amount_mask(blinding_factors[0]);

                const masked_amount = await crypto.toggle_masked_amount(amount_mask, amount);

                const unmasked_amount = await crypto.toggle_masked_amount(amount_mask, masked_amount);

                const amount_mask2 = await crypto.generate_amount_mask(blinding_factors[1]);

                const unmasked_amount2 = await crypto.toggle_masked_amount(amount_mask2, masked_amount);

                assert.notEqual(masked_amount, unmasked_amount);
                assert.equal(unmasked_amount.toJSNumber(), amount);
                assert.notEqual(unmasked_amount2, unmasked_amount);
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

                    assert(await crypto.check_bulletproof([proof], [commitments]));
                });

                it('Batched Verification', async () => {
                    const valid = await crypto.check_bulletproof(
                        [proof, proof], [commitments, commitments]);

                    assert(valid);
                });

                it('Big Batch Verification', async () => {
                    const valid = await crypto.check_bulletproof(
                        [proof, proof, proof, proof, proof, proof],
                        [commitments, commitments, commitments, commitments, commitments, commitments]);

                    assert(valid);
                });

                it('Fail Verification', async () => {
                    const fake_commitments = await crypto.random_points(1);

                    assert(!await crypto.check_bulletproof([proof], [fake_commitments]));
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

                    assert(pass === true);
                });

                it('Batched Verification', async () => {
                    const pass = await crypto.check_bulletproof_plus(
                        [proof, proof], [commitments, commitments]);

                    assert(pass === true);
                });

                it('Big Batch Verification', async () => {
                    const pass = await crypto.check_bulletproof_plus(
                        [proof, proof, proof, proof, proof, proof],
                        [commitments, commitments, commitments, commitments, commitments, commitments]);

                    assert(pass === true);
                });

                it('Fail Verification', async () => {
                    const fake_commitments = await crypto.random_points(1);

                    const pass = await crypto.check_bulletproof_plus([proof], [fake_commitments]);

                    assert(pass === false);
                });
            });
        });

        describe('Check User Config', async () => {
            const sha3 = async (input: string): Promise<string> => {
                try {
                    input = JSON.parse(input);
                    const hash = sha3_256(Buffer.from(input, is_hex(input) ? 'hex' : undefined));

                    return make_module_result(false, hash);
                } catch (error: any) {
                    return make_module_result(true, undefined, 'External call failure');
                }
            };

            const INPUT_DATA = 'cfc765d905c65e2b61816dc1f0fd69f6f6779f36ed6239ac7e21ff51ef2c891e';
            const HASH = '974506601a60dc465e6e9acddb563889e63471849ec4198656550354b8541fcb';

            it('Test #1', async () => {
                crypto.external_library.sha3 = sha3;

                const result = await crypto.sha3(INPUT_DATA);

                assert(result === HASH);
            });
        });
    });
})();
