// Copyright (c) 2020, Brandon Lehmann
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

import {
    Library,
    crypto_borromean_signature_t,
    crypto_bulletproof_plus_t,
    crypto_bulletproof_t,
    crypto_clsag_signature_t,
    crypto_entropy_t,
    crypto_triptych_signature_t,
    key_pair_t,
    Language,
    ICryptoLibrary,
    LibraryType,
    ModuleSettings,
    ModuleResult
} from './types';
import { LibraryTypeName, is_hex } from './helpers';
import { uint256 } from './uint64';
import { Buffer } from 'buffer';

export * from './types';
export * from './helpers';

/**
 * @ignore
 */
export abstract class CryptoModule {
    private static _external_library: Partial<ICryptoLibrary> = {};
    protected static runtime_configuration: ModuleSettings = {
        type: LibraryType.UNKNOWN
    };

    /**
     * We cannot create a new instance using this method as we need to await the
     * loading of an underlying module, hence, we need to await the static
     * init() method on this class to receive an instance of the class
     *
     * @protected
     */
    // eslint-disable-next-line no-useless-constructor
    protected constructor () {}

    /**
     * Gets the external library calls that replace our cryptographic method calls
     */
    public static get external_library (): Partial<ICryptoLibrary> {
        return this._external_library;
    }

    /**
     * Sets external library calls that replace our cryptographic method calls
     *
     * @param config
     */
    public static set external_library (config: Partial<ICryptoLibrary>) {
        for (const key of Object.keys(config)) {
            this._external_library[key] = config[key];
        }
    }

    /**
     * Returns the underlying cryptographic library name
     */
    public static get library_name (): string {
        return LibraryTypeName(this.runtime_configuration.type);
    }

    /**
     * Returns the underlying cryptographic library type
     */
    public static get library_type (): LibraryType {
        return this.runtime_configuration.type;
    }

    /**
     * Returns if the underlying cryptographic library is of the
     * Node.js C++ Addon type
     */
    public static get is_native (): boolean {
        return this.runtime_configuration.type === LibraryType.NODE;
    }

    /**
     * Sets external library calls that replace our cryptographic method calls
     *
     * @param config
     */
    public set external_library (config: Partial<ICryptoLibrary>) {
        CryptoModule.external_library = config;
    }

    /**
     * Gets the external library calls that replace our cryptographic method calls
     */
    public get external_library (): Partial<ICryptoLibrary> {
        return CryptoModule.external_library;
    }

    /**
     * Returns the underlying cryptographic library name
     */
    public get library_name (): string {
        return CryptoModule.library_name;
    }

    /**
     * Returns the underlying cryptographic library type
     */
    public get library_type (): LibraryType {
        return CryptoModule.library_type;
    }

    /**
     * Returns if the underlying cryptographic library is of the
     * Node.js C++ Addon type
     */
    public get is_native (): boolean {
        return CryptoModule.is_native;
    }

    /**
     * Encodes an address into Base58
     *
     * @param prefix
     * @param public_spend
     * @param public_view
     */
    public async base58_address_encode (
        prefix: number,
        public_spend: string,
        public_view?: string
    ): Promise<string> {
        if (public_view) {
            return this.execute('base58_address_encode', {
                prefix,
                public_spend,
                public_view
            });
        }

        return this.execute('base58_address_encode', {
            prefix,
            public_key: public_spend
        });
    }

    /**
     * Encodes an address into CryptoNote Base58
     *
     * @param prefix
     * @param public_spend
     * @param public_view
     */
    public async cn_base58_address_encode (
        prefix: number,
        public_spend: string,
        public_view?: string
    ): Promise<string> {
        if (public_view) {
            return this.execute('cn_base58_address_encode', {
                prefix,
                public_spend,
                public_view
            });
        }

        return this.execute('cn_base58_address_encode', {
            prefix,
            public_key: public_spend
        });
    }

    /**
     * Decodes an address from Base58
     *
     * @param base58
     */
    public async base58_address_decode (base58: string): Promise<{
        prefix: number,
        public_spend: string,
        public_view?: string
    }> {
        const result = await this.execute<{
            prefix: number,
            public_spend: string,
            public_view?: string
        }>('base58_address_decode', base58);

        if (result.public_view && uint256.from(result.public_view).value === BigInt(1)) {
            delete result.public_view;
        }

        return result;
    }

    /**
     * Decodes an address from CryptoNote Base58
     *
     * @param base58
     */
    public async cn_base58_address_decode (base58: string): Promise<{
        prefix: number,
        public_spend: string,
        public_view?: string
    }> {
        const result = await this.execute<{
            prefix: number,
            public_spend: string,
            public_view?: string
        }>('cn_base58_address_decode', base58);

        if (result.public_view && uint256.from(result.public_view).value === BigInt(1)) {
            delete result.public_view;
        }

        return result;
    }

    /**
     * Generates a random entropy value
     *
     * @param entropy
     * @param bits
     * @param encode_timestamp
     */
    public async random_entropy (
        entropy?: string,
        bits: 128 | 256 = 256,
        encode_timestamp = true
    ): Promise<crypto_entropy_t> {
        return await this.execute<crypto_entropy_t>('random_entropy', {
            entropy: entropy ?? '',
            bits,
            encode_timestamp
        });
    }

    /**
     * Generates a random hash value
     */
    public async random_hash (): Promise<string> {
        return await this.execute('random_hash');
    }

    /**
     * Generates a list of random hashes
     *
     * @param count
     */
    public async random_hashes (count = 1): Promise<string[]> {
        return await this.execute('random_hashes', count);
    }

    /**
     * Generates a random ED25519 scalar value
     */
    public async random_scalar (): Promise<string> {
        return await this.execute('random_scalar');
    }

    /**
     * Generates a list of random ED25519 scalars
     *
     * @param count
     */
    public async random_scalars (count = 1): Promise<string[]> {
        return await this.execute('random_scalars', count);
    }

    /**
     * Generates a random ED25519 point value
     */
    public async random_point (): Promise<string> {
        return await this.execute('random_point');
    }

    /**
     * Generates a list of random ED25519 points
     *
     * @param count
     */
    public async random_points (count = 1): Promise<string[]> {
        return await this.execute('random_points', count);
    }

    /**
     * Hashes the input data using sha256 and returns the resulting hash value
     *
     * @param input
     */
    public async sha256 (input: any): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('sha256', input);
    }

    /**
     * Hashes the input data using sha384 and returns the resulting hash value
     *
     * @param input
     */
    public async sha384 (input: any): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('sha384', input);
    }

    /**
     * Hashes the input data using sha512 and returns the resulting hash value
     *
     * @param input
     */
    public async sha512 (input: any): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('sha512', input);
    }

    /**
     * Hashes the input data using sha3 and returns the resulting hash value
     *
     * @param input
     */
    public async sha3 (input: any): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('sha3', input);
    }

    /**
     * Hashes the input data using a simple SHA3 KDF function and returns
     * the resulting hash value
     *
     * @param input
     * @param iterations
     */
    public async sha3_slow (input: string, iterations = 0): Promise<string> {
        return this.execute('sha3_slow', {
            input,
            iterations
        });
    }

    /**
     * Hashes the input data using Blake2b and returns the resulting
     * hash value
     *
     * @param input
     */
    public async blake2b (input: any): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('blake2b', input);
    }

    /**
     * Hashes the input data using Argon2i and returns the resulting hash value
     *
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     */
    public async argon2i (
        input: any,
        iterations = 1,
        memory = 256,
        threads = 1
    ): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('argon2i', {
            input,
            iterations,
            memory,
            threads
        });
    }

    /**
     * Hashes the input data using Argon2d and returns the resulting hash value
     *
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     */
    public async argon2d (
        input: any,
        iterations = 1,
        memory = 256,
        threads = 1
    ): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('argon2d', {
            input,
            iterations,
            memory,
            threads
        });
    }

    /**
     * Hashes the input data using Argon2id and returns the resulting hash value
     *
     * @param input
     * @param iterations
     * @param memory
     * @param threads
     */
    public async argon2id (
        input: any,
        iterations = 1,
        memory = 256,
        threads = 1
    ): Promise<string> {
        if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('argon2id', {
            input,
            iterations,
            memory,
            threads
        });
    }

    /**
     * Recovers entropy from a mnemonic phrase or a list of mnemonic phrase words
     *
     * @param mnenomic_phrase
     * @param language
     */
    public async entropy_recover (
        mnenomic_phrase: string | string[],
        language: Language = Language.ENGLISH
    ): Promise<crypto_entropy_t> {
        if (Array.isArray(mnenomic_phrase)) {
            mnenomic_phrase = mnenomic_phrase.join(' ');
        }

        return this.execute('entropy_recover', {
            input: mnenomic_phrase,
            language
        });
    }

    /**
     * Generates a key derivation
     *
     * Note: D = (a * B) mod l
     *
     * @param public_key
     * @param secret_key
     */
    public async generate_derivation (public_key: string, secret_key: string): Promise<string> {
        return this.execute('generate_derivation', {
            public_key,
            secret_key
        });
    }

    /**
     * Generates a key derivation scalar value
     *
     * Note: Ds = H(D || output_index) mod l
     *
     * @param derivation
     * @param output_index
     */
    public async generate_derivation_scalar (derivation: string, output_index = 0): Promise<string> {
        return this.execute('generate_derivation_scalar', {
            derivation,
            output_index
        });
    }

    /**
     * Derives a public ephemeral from a derivation scalar and a public key
     *
     * Note: P = [(Ds * G) + B] mod l
     *
     * @param derivation_scalar
     * @param public_key
     */
    public async derive_public_key (derivation_scalar: string, public_key: string): Promise<string> {
        return this.execute('derive_public_key', {
            derivation_scalar,
            public_key
        });
    }

    /**
     * Derives a secret ephemeral from a derivation scalar and a secret key
     *
     * Note: p = (Ds + b) mod l
     *
     * @param derivation_scalar
     * @param secret_key
     */
    public async derive_secret_key (derivation_scalar: string, secret_key: string): Promise<string> {
        return this.execute('derive_secret_key', {
            derivation_scalar,
            secret_key
        });
    }

    /**
     * Generates a key image from the public and secret ephemeral
     *
     * @param public_ephemeral
     * @param secret_ephemeral
     */
    public async generate_key_image (public_ephemeral: string, secret_ephemeral: string): Promise<string> {
        return this.execute('generate_key_image', {
            public_ephemeral,
            secret_ephemeral
        });
    }

    /**
     * Generates a V2 key image from the secret ephemeral
     *
     * @param secret_ephemeral
     */
    public async generate_key_image_v2 (secret_ephemeral: string): Promise<string> {
        return this.execute('generate_key_image_v2', secret_ephemeral);
    }

    /**
     * Generates a secret & public key pair
     */
    public async generate_keys (): Promise<key_pair_t> {
        return this.execute('generate_keys');
    }

    /**
     * Generates a list pf secret & public keys
     *
     * @param count
     */
    public async generate_keys_m (count = 1): Promise<{ public_keys: string[], secret_keys: string[] }> {
        return this.execute('generate_keys_m', count);
    }

    /**
     * Much like derive_public_key() but calculates the public_key used from the public ephemeral
     *
     * Note: B = P - [H(D || output_index) mod l]
     *
     * @param derivation
     * @param public_ephemeral
     * @param output_index
     */
    public async underive_public_key (derivation: string, public_ephemeral: string, output_index = 0) {
        return this.execute('underive_public_key', {
            derivation,
            output_index,
            public_ephemeral
        });
    }

    /**
     * Calculates the public key of the given secret key
     *
     * @param secret_key
     */
    public async secret_key_to_public_key (secret_key: string): Promise<string> {
        return this.execute('secret_key_to_public_key', secret_key);
    }

    /**
     * Calculates the secret scalar and public key for the provided ED25519 private key (aka seed)
     *
     * @param private_key
     */
    public async private_key_to_keys (private_key: string): Promise<key_pair_t> {
        return this.execute('private_key_to_keys', private_key);
    }

    /**
     * Generates an ED25519 point by hashing the provided data and turning
     * it into a point on the ED25519 curve
     *
     * @param input
     */
    public async hash_to_point (input: any): Promise<string> {
        if (input instanceof Buffer) {
            return this.execute('hash_to_point', input.toString('hex'));
        } else if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('hash_to_point', input);
    }

    /**
     * Generates an ED25519 scalar by hashing the provided data and
     * reducing it to an ED25519 scalar value
     *
     * @param input
     */
    public async hash_to_scalar (input: any): Promise<string> {
        if (input instanceof Buffer) {
            return this.execute('hash_to_scalar', input.toString('hex'));
        } else if (typeof input !== 'string') {
            input = JSON.stringify(input);
        }

        return this.execute('hash_to_scalar', input);
    }

    /**
     * Reduces the input value to an ED25519 scalar value
     *
     * @param input
     */
    public async scalar_reduce (input: string | Buffer): Promise<string> {
        if (input instanceof Buffer) {
            return this.execute('scalar_reduce', input.subarray(0, 32).toString('hex'));
        }

        return this.execute('scalar_reduce', input);
    }

    /**
     * Calculates the depth of the Merkle tree based upon how many hashes
     * the tree contains
     *
     * @param value
     */
    public async tree_depth (value: number): Promise<number> {
        return this.execute('tree_depth', value);
    }

    /**
     * Generates the root Merkle tree hash using the list of hashes
     *
     * @param hashes
     */
    public async root_hash (hashes: string[]): Promise<string> {
        return this.execute('root_hash', { items: hashes });
    }

    /**
     * Generates a Merkle tree root hash value from the supplied input values
     *
     * @param branches
     * @param leaf
     * @param depth
     * @param path
     */
    public async root_hash_from_branch (branches: string[], leaf: string, depth = 0, path: 0 | 1 = 0): Promise<string> {
        return this.execute('root_hash_from_branch', {
            branches,
            depth,
            leaf,
            path
        });
    }

    /**
     * Generates Merkle tree branch from the list of hashes
     *
     * @param hashes
     */
    public async tree_branch (hashes: string[]): Promise<string[]> {
        return this.execute('tree_branch', { items: hashes });
    }

    /**
     * Generates an ED25519 RFC8032 signature for the message using
     * the secret key specified
     * @param message
     * @param secret_key
     */
    public async generate_rfc8032_signature (message: string, secret_key: string): Promise<string> {
        return this.execute('generate_rfc8032_signature', {
            message,
            secret_key
        });
    }

    /**
     * Checks an ED25519 RFC8032 signature to verify that it was created
     * with the secret key of the public key specified
     * @param message
     * @param public_key
     * @param signature
     */
    public async check_rfc8032_signature (message: string, public_key: string, signature: string): Promise<boolean> {
        try {
            await this.execute('check_rfc8032_signature', {
                message,
                public_key,
                signature
            });

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates a simple ED25519 signature for the message digest using
     * the secret key specified
     *
     * @param message_digest
     * @param secret_key
     */
    public async generate_signature (message_digest: string, secret_key: string): Promise<string> {
        return this.execute('generate_signature', {
            message_digest,
            secret_key
        });
    }

    /**
     * Prepares a signature for the message digest such that it
     * can be completed in later stages of the signature construction
     *
     * @param message_digest
     * @param public_key
     */
    public async prepare_signature (message_digest: string, public_key: string): Promise<string> {
        return this.execute('prepare_signature', {
            message_digest,
            public_key
        });
    }

    /**
     * Completes a previously prepared signature
     *
     * @param secret_key
     * @param signature
     */
    public async complete_signature (secret_key: string, signature: string): Promise<string> {
        return this.execute('complete_signature', {
            secret_key,
            signature
        });
    }

    /**
     * Checks a simple ED25519 signature to verify that it was created
     * with the secret key of the public key specified
     *
     * @param message_digest
     * @param public_key
     * @param signature
     */
    public async check_signature (message_digest: string, public_key: string, signature: string): Promise<boolean> {
        try {
            await this.execute('check_signature', {
                message_digest,
                public_key,
                signature
            });

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates a borromean ring signature for the message digest using
     * the secret key specified and the list of all possible public key
     * signing candidates
     *
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     */
    public async generate_borromean_signature (
        message_digest: string,
        secret_ephemeral: string,
        public_keys: string[]
    ): Promise<crypto_borromean_signature_t> {
        return this.execute('generate_borromean_signature', {
            message_digest,
            secret_ephemeral,
            public_keys
        } as Library.GenerateRingSignature);
    }

    /**
     * Prepares a borromean ring signature for the message digest such
     * that it can be completed in later stages of signature construction
     *
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     */
    public async prepare_borromean_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        real_output_index: number
    ): Promise<crypto_borromean_signature_t> {
        return this.execute('prepare_borromean_signature', {
            message_digest,
            key_image,
            public_keys,
            real_output_index
        } as Library.GenerateRingSignature);
    }

    /**
     * Completes a previously prepared borromean ring signature
     *
     * @param secret_ephemeral
     * @param real_output_index
     * @param signature
     */
    public async complete_borromean_signature (
        secret_ephemeral: string,
        real_output_index: number,
        signature: crypto_borromean_signature_t
    ): Promise<crypto_borromean_signature_t> {
        return this.execute('complete_borromean_signature', {
            secret_ephemeral,
            real_output_index,
            signature
        } as Library.GenerateRingSignature<crypto_borromean_signature_t>);
    }

    /**
     * Checks a borromean ring signature to verify that it was created
     * by one of the candidate public keys
     *
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     */
    public async check_borromean_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        signature: crypto_borromean_signature_t
    ): Promise<boolean> {
        try {
            await this.execute('check_borromean_signature', {
                message_digest,
                key_image,
                public_keys,
                signature
            } as Library.CheckRingSignature<crypto_borromean_signature_t>);

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates a CLSAG ring signature for the message digest using
     * the secret key specified and the list of all possible public
     * key signing candidates.
     *
     * Optionally, we also include proof that we have the real values
     * of the values hidden within pedersen commitments
     *
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     */
    public async generate_clsag_signature (
        message_digest: string,
        secret_ephemeral: string,
        public_keys: string[],
        input_blinding_factor?: string,
        public_commitments?: string[],
        pseudo_blinding_factor?: string,
        pseudo_commitment?: string
    ): Promise<crypto_clsag_signature_t> {
        const options: Library.GenerateRingSignature = {
            message_digest,
            secret_ephemeral,
            public_keys
        };

        if (input_blinding_factor) {
            options.input_blinding_factor = input_blinding_factor;
        }

        if (public_commitments) {
            options.public_commitments = public_commitments;
        }

        if (pseudo_blinding_factor) {
            options.pseudo_blinding_factor = pseudo_blinding_factor;
        }

        if (pseudo_commitment) {
            options.pseudo_commitment = pseudo_commitment;
        }

        return this.execute('generate_clsag_signature', options);
    }

    /**
     * Prepares a CLSAG ring signature for the message digest such
     * that it can be completed in later stages of signature
     * construction
     *
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     */
    public async prepare_clsag_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        real_output_index: number,
        input_blinding_factor?: string,
        public_commitments?: string[],
        pseudo_blinding_factor?: string,
        pseudo_commitment?: string
    ): Promise<{ signature: crypto_clsag_signature_t, h: string[], mu_P: string }> {
        const options: Library.GenerateRingSignature = {
            message_digest,
            key_image,
            public_keys,
            real_output_index
        };

        if (input_blinding_factor) {
            options.input_blinding_factor = input_blinding_factor;
        }

        if (public_commitments) {
            options.public_commitments = public_commitments;
        }

        if (pseudo_blinding_factor) {
            options.pseudo_blinding_factor = pseudo_blinding_factor;
        }

        if (pseudo_commitment) {
            options.pseudo_commitment = pseudo_commitment;
        }

        return this.execute('prepare_clsag_signature', options);
    }

    /**
     * Completes a previously prepared CLSAG ring signature
     *
     * @param secret_ephemeral
     * @param real_output_index
     * @param signature
     * @param h
     * @param mu_P
     */
    public async complete_clsag_signature (
        secret_ephemeral: string,
        real_output_index: number,
        signature: crypto_clsag_signature_t,
        h: string[],
        mu_P: string
    ): Promise<crypto_clsag_signature_t> {
        return this.execute('complete_clsag_signature', {
            secret_ephemeral,
            real_output_index,
            signature,
            h,
            mu_P
        } as Library.GenerateRingSignature<crypto_clsag_signature_t>);
    }

    /**
     * Checks a CLSAG ring signature to verify that it was created
     * by one of the candidate public keys.
     *
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     * @param commitments
     */
    public async check_clsag_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        signature: crypto_clsag_signature_t,
        commitments?: string[]
    ): Promise<boolean> {
        try {
            const options: Library.CheckRingSignature<crypto_clsag_signature_t> = {
                message_digest,
                key_image,
                public_keys,
                signature
            };

            if (commitments) {
                options.commitments = commitments;
            }

            await this.execute('check_clsag_signature', options);

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates a Triptych ring signature for the message digest using
     * the secret key specified and the list of all possible public
     * key signing candidates.
     *
     * Optionally, we also include proof that we have the real values
     * of the values hidden within pedersen commitments
     *
     * @param message_digest
     * @param secret_ephemeral
     * @param public_keys
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     */
    public async generate_triptych_signature (
        message_digest: string,
        secret_ephemeral: string,
        public_keys: string[],
        input_blinding_factor: string,
        public_commitments: string[],
        pseudo_blinding_factor: string,
        pseudo_commitment: string
    ): Promise<crypto_triptych_signature_t> {
        const options: Library.GenerateRingSignature = {
            message_digest,
            secret_ephemeral,
            public_keys
        };

        if (input_blinding_factor) {
            options.input_blinding_factor = input_blinding_factor;
        }

        if (public_commitments) {
            options.public_commitments = public_commitments;
        }

        if (pseudo_blinding_factor) {
            options.pseudo_blinding_factor = pseudo_blinding_factor;
        }

        if (pseudo_commitment) {
            options.pseudo_commitment = pseudo_commitment;
        }

        return this.execute('generate_triptych_signature', options);
    }

    /**
     * Prepares a Triptych ring signature for the message digest such
     * that it can be completed in later stages of signature
     * construction
     *
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param real_output_index
     * @param input_blinding_factor
     * @param public_commitments
     * @param pseudo_blinding_factor
     * @param pseudo_commitment
     */
    public async prepare_triptych_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        real_output_index: number,
        input_blinding_factor: string,
        public_commitments: string[],
        pseudo_blinding_factor: string,
        pseudo_commitment: string
    ): Promise<{ signature: crypto_triptych_signature_t, xpow: string }> {
        const options: Library.GenerateRingSignature = {
            message_digest,
            key_image,
            public_keys,
            real_output_index
        };

        if (input_blinding_factor) {
            options.input_blinding_factor = input_blinding_factor;
        }

        if (public_commitments) {
            options.public_commitments = public_commitments;
        }

        if (pseudo_blinding_factor) {
            options.pseudo_blinding_factor = pseudo_blinding_factor;
        }

        if (pseudo_commitment) {
            options.pseudo_commitment = pseudo_commitment;
        }

        return this.execute('prepare_triptych_signature', options);
    }

    /**
     * Completes a previously prepared Triptych ring signature
     *
     * @param secret_ephemeral
     * @param signature
     * @param xpow
     */
    public async complete_triptych_signature (
        secret_ephemeral: string,
        signature: crypto_triptych_signature_t,
        xpow: string
    ): Promise<crypto_triptych_signature_t> {
        return this.execute('complete_triptych_signature', {
            secret_ephemeral,
            signature,
            xpow
        } as Library.GenerateRingSignature<crypto_triptych_signature_t>);
    }

    /**
     * Checks a Triptych ring signature to verify that it was created
     * by one of the candidate public keys.
     *
     * @param message_digest
     * @param key_image
     * @param public_keys
     * @param signature
     * @param commitments
     */
    public async check_triptych_signature (
        message_digest: string,
        key_image: string,
        public_keys: string[],
        signature: crypto_triptych_signature_t,
        commitments: string[]
    ): Promise<boolean> {
        try {
            const options: Library.CheckRingSignature<crypto_triptych_signature_t> = {
                message_digest,
                key_image,
                public_keys,
                signature
            };

            if (commitments) {
                options.commitments = commitments;
            }

            await this.execute('check_triptych_signature', options);

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates a Bulletproof Zero-Knowledge proof of the amount(s) specified
     *
     * @param amounts
     * @param blinding_factors
     * @param N
     */
    public async generate_bulletproof (
        amounts: number[],
        blinding_factors: string[],
        N = 64
    ): Promise<{ proof: crypto_bulletproof_t, commitments: string[] }> {
        return this.execute('generate_bulletproof', {
            amounts,
            blinding_factors,
            N
        });
    }

    /**
     * Checks that a Bulletproof proof is valid
     *
     * @param proof
     * @param commitments
     * @param N
     */
    public async check_bulletproof (
        proof: crypto_bulletproof_t | crypto_bulletproof_t[],
        commitments: string[] | string[][],
        N = 64
    ): Promise<boolean> {
        try {
            if (Array.isArray(proof) && Array.isArray(commitments[0])) {
                await this.execute('check_bulletproof_batch', {
                    proofs: proof,
                    commitments,
                    N
                });
            } else {
                await this.execute('check_bulletproof', {
                    proof,
                    commitments,
                    N
                });
            }

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates a Bulletproof+ Zero-Knowledge proof of the amount(s) specified
     *
     * @param amounts
     * @param blinding_factors
     * @param N
     */
    public async generate_bulletproof_plus (
        amounts: number[],
        blinding_factors: string[],
        N = 64
    ): Promise<{ proof: crypto_bulletproof_plus_t, commitments: string[] }> {
        return this.execute('generate_bulletproof', {
            amounts,
            blinding_factors,
            N
        });
    }

    /**
     * Checks that a Bulletproof+ proof is valid
     *
     * @param proof
     * @param commitments
     * @param N
     */
    public async check_bulletproof_plus (
        proof: crypto_bulletproof_plus_t | crypto_bulletproof_plus_t[],
        commitments: string[] | string[][],
        N = 64
    ): Promise<boolean> {
        try {
            if (Array.isArray(proof) && Array.isArray(commitments[0])) {
                await this.execute('check_bulletproof_batch', {
                    proofs: proof,
                    commitments,
                    N
                });
            } else {
                await this.execute('check_bulletproof', {
                    proof,
                    commitments,
                    N
                });
            }

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Verifies that the sum of output pedersen commitments plus a pedersen
     * commitment of the transaction fee are equal to the sum of pseudo
     * pedersen commitments
     *
     * @param pseudo_commitments
     * @param output_commitments
     * @param transaction_fee
     */
    public async check_commitments_parity (
        pseudo_commitments: string[],
        output_commitments: string[],
        transaction_fee: number
    ): Promise<boolean> {
        try {
            await this.execute('check_commitments_parity', {
                pseudo_commitments,
                output_commitments,
                transaction_fee
            });

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Generates the amount mask for the given deriviation scalar
     *
     * @param derivation_scalar
     */
    public async generate_amount_mask (derivation_scalar: string): Promise<string> {
        return this.execute('generate_amount_mask', derivation_scalar);
    }

    /**
     * Generates the commitment blinding factor for the given derivation scalar
     *
     * @param derivation_scalar
     */
    public async generate_commitment_blinding_factor (derivation_scalar: string): Promise<string> {
        return this.execute('generate_commitment_blinding_factor', derivation_scalar);
    }

    /**
     * Generates a pedersen commitment for the supplied blinding factor and amount
     *
     * Note: C = (y * G) + (a * H) mod l
     *
     * @param blinding_factor
     * @param amount
     */
    public async generate_pedersen_commitment (blinding_factor: string, amount: number): Promise<string> {
        return this.execute('generate_pedersen_commitment', {
            blinding_factor,
            amount
        });
    }

    /**
     * Generates a list of random blinding factors and pseudo output commitments from
     * the list of input amounts and the output commitments while proving them to a zero-sum
     *
     * @param amounts
     * @param output_blinding_factors
     */
    public async generate_pseudo_commitments (
        amounts: number[],
        output_blinding_factors: string[]
    ): Promise<{ blinding_factors: string[], commitments: string[] }> {
        return this.execute('generate_pseudo_commitments', {
            amounts,
            output_blinding_factors
        });
    }

    /**
     * Toggles an amount from unmasked/masked to the inverse state of masked/unmasked using the
     * provided amount mask
     *
     * @param amount_mask
     * @param amount
     */
    public async toggle_masked_amount (
        amount_mask: string,
        amount: string | number | bigint
    ): Promise<bigint> {
        if (typeof amount === 'number') {
            amount = BigInt(amount);
        } else if (typeof amount === 'string') {
            amount = uint256.from(amount).value;
        }

        const result = await this.execute('toggle_masked_amount', {
            amount_mask,
            amount: uint256(amount).toString()
        });

        return uint256.from(result).value;
    }

    /**
     * Generates proof of having the secret ephemerals specified by generating the
     * relevant public keys, key_images, and signature for each and encoding the
     * necessary information into a Base58 encoded string that can be provided
     * to a verified that already has the public ephemerals
     *
     * @param secret_ephemerals
     */
    public async generate_outputs_proof (
        secret_ephemerals: string[]
    ): Promise<string> {
        return this.execute('generate_outputs_proof', { items: secret_ephemerals });
    }

    /**
     * Verifies the proof provides using the public ephemerals by decoding the Base58 proof,
     * extracting the key images, the signatures, and then verifying if those signatures
     * are all valid, in which case, the key images are returned
     *
     * @param public_ephemerals
     * @param proof
     */
    public async check_outputs_proof (
        public_ephemerals: string[],
        proof: string
    ): Promise<string[]> {
        return this.execute('check_outputs_proof', {
            public_ephemerals,
            proof
        });
    }

    /**
     * Encodes the value specified into Base58
     *
     * @param value
     */
    public async base58_encode (value: string | Buffer): Promise<string> {
        if (typeof value === 'string') {
            value = Buffer.from(value, is_hex(value) ? 'hex' : undefined);
        }

        return this.execute('base58_encode', value.toString('hex'));
    }

    /**
     * Encodes the value specified into Base58 and appends a checksum to the result
     *
     * @param value
     */
    public async base58_encode_check (value: string | Buffer): Promise<string> {
        if (typeof value === 'string') {
            value = Buffer.from(value, is_hex(value) ? 'hex' : undefined);
        }

        return this.execute('base58_encode_check', value.toString('hex'));
    }

    /**
     * Decodes a Base58 encoded string
     *
     * @param base58
     */
    public async base58_decode (base58: string): Promise<Buffer> {
        const result = await this.execute('base58_decode', base58);

        return Buffer.from(result, 'hex');
    }

    /**
     * Decodes a Base58 encoded string after verifying the checksum value included
     *
     * @param base58
     */
    public async base58_decode_check (base58: string): Promise<Buffer> {
        const result = await this.execute('base58_decode_check', base58);

        return Buffer.from(result, 'hex');
    }

    /**
     * Encodes the specified value into CryptoNote Base58
     * @param value
     */
    public async cn_base58_encode (value: string | Buffer): Promise<string> {
        if (typeof value === 'string') {
            value = Buffer.from(value, is_hex(value) ? 'hex' : undefined);
        }

        return this.execute('cn_base58_encode', value.toString('hex'));
    }

    /**
     * Encodes the value specified into CryptoNote Base58 and appends a checksum to the result
     *
     * @param value
     */
    public async cn_base58_encode_check (value: string | Buffer): Promise<string> {
        if (typeof value === 'string') {
            value = Buffer.from(value, is_hex(value) ? 'hex' : undefined);
        }

        return this.execute('cn_base58_encode_check', value.toString('hex'));
    }

    /**
     * Decodes a CryptoNote Base58 string
     *
     * @param base58
     */
    public async cn_base58_decode (base58: string): Promise<Buffer> {
        const result = await this.execute('cn_base58_decode', base58);

        return Buffer.from(result, 'hex');
    }

    /**
     * Decodes a CryptoNote Base58 encoded string after verifying the checkvalue value included
     *
     * @param base58
     */
    public async cn_base58_decode_check (base58: string): Promise<Buffer> {
        const result = await this.execute('cn_base58_decode_check', base58);

        return Buffer.from(result, 'hex');
    }

    /**
     * Generates a pedersen commitment for a transaction fee
     *
     * @param amount
     */
    public async generate_transaction_fee_commitment (amount: number): Promise<string> {
        return this.generate_pedersen_commitment(''.padEnd(64, '0'), amount);
    }

    /**
     * Checks if the value provided is a valid ED25519 scalar
     *
     * @param value
     */
    public async check_scalar (value: string): Promise<boolean> {
        try {
            await this.execute('check_scalar', value);

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Checks if the value provided is a valid ED25519 point
     * @param value
     */
    public async check_point (value: string): Promise<boolean> {
        try {
            await this.execute('check_point', value);

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Encodes the supplied seed into a list of mnemonic words
     *
     * @param entropy
     * @param language
     */
    public async mnemonics_encode (
        entropy: string,
        language: Language = Language.ENGLISH
    ): Promise<string[]> {
        const result = await this.execute('mnemonics_encode', { entropy, language });

        return result.split(' ');
    }

    /**
     * Decodes a mnemonic phrase or list of mnenomic words into as seed value
     *
     * @param mnemonic
     * @param language
     */
    public async mnemonics_decode (
        mnemonic: string | string[],
        language: Language = Language.ENGLISH
    ): Promise<crypto_entropy_t> {
        if (Array.isArray(mnemonic)) {
            mnemonic = mnemonic.join(' ');
        }

        return this.execute('mnemonics_decode', {
            input: mnemonic,
            language
        });
    }

    /**
     * Returns the index number of the specified mnemonic word
     *
     * @param word
     * @param language
     */
    public async mnemonics_word_index (
        word: string,
        language: Language = Language.ENGLISH
    ): Promise<number> {
        return this.execute('mnemonics_word_index', {
            input: word,
            language
        });
    }

    /**
     * Returns the list of mnemonic words
     *
     * @param language
     */
    public async word_list (language: Language = Language.ENGLISH): Promise<string[]> {
        const result = await this.execute('word_list', {
            language
        });

        return result.split(' ');
    }

    /**
     * Returns the list of mnemonic words that have been trimmed to
     * the minimum number of characters per word
     *
     * @param language
     */
    public async word_list_trimmed (language: Language = Language.ENGLISH): Promise<string[]> {
        const result = await this.execute('word_list_trimmed', {
            language
        });

        return result.split(' ');
    }

    /**
     * Calculates the exponent of 2^e that matches the target value
     *
     * @param value
     */
    public async calculate_base2_exponent (value: number): Promise<number> {
        return this.execute('calculate_base2_exponent', value);
    }

    /**
     * Encrypts the provides string using the supplied password into a hexadecimal encoded string
     *
     * @param input
     * @param password
     * @param iterations
     */
    public async aes_encrypt<InputType = string> (
        input: InputType,
        password: string,
        iterations?: number
    ): Promise<string> {
        if (typeof input !== 'string') {
            (input as string) = JSON.stringify(input);
        }

        const options: Library.AES = {
            input: (input as string),
            password
        };

        if (iterations) {
            options.iterations = iterations;
        }

        return this.execute('aes_encrypt', options);
    }

    /**
     * Decrypts the data from the provided hexidecimal encoded encrypted string using the supplied password
     *
     * @param input
     * @param password
     * @param iterations
     */
    public async aes_decrypt<OutputType = string> (
        input: string,
        password: string,
        iterations?: number
    ): Promise<OutputType> {
        const options: Library.AES = {
            input,
            password
        };

        if (iterations) {
            options.iterations = iterations;
        }

        return this.execute('aes_decrypt', options);
    }

    /**
     * Returns a list of the supported languages
     */
    public async languages (): Promise<Language[]> {
        return this.execute('languages');
    }

    /**
     * Generates a BIP-39 seed from the provided entropy
     *
     * @param entropy
     * @param passphrase
     */
    public async generate_seed (
        entropy: string,
        passphrase = ''
    ): Promise<string> {
        return this.execute('generate_seed', {
            entropy,
            passphrase
        });
    }

    /**
     * Generates a Hierarchical Deterministic Key Pair using the provided path
     *
     * @param seed
     * @param purposeOrPath the purpose (numeric) or path (e.g. m/44'/0'/1/3)
     * @param coin_type
     * @param account
     * @param change
     * @param address_index
     * @param hmac_key
     */
    public async generate_child_key (
        seed: string,
        purposeOrPath?: number | string,
        coin_type?: number,
        account?: number,
        change?: number,
        address_index?: number,
        hmac_key = 'ed25519 seed'
    ): Promise<key_pair_t> {
        const input: any = {
            seed,
            hmac_key
        };

        if (typeof purposeOrPath === 'string') {
            input.path = purposeOrPath.toLowerCase(); // makes sure our m is lowercase
        } else {
            if (typeof purposeOrPath !== 'undefined') input.purpose = purposeOrPath;
            if (typeof coin_type !== 'undefined') input.coin_type = coin_type;
            if (typeof account !== 'undefined') input.account = account;
            if (typeof change !== 'undefined') input.change = change;
            if (typeof address_index !== 'undefined') input.address_index = address_index;
        }

        return this.execute('generate_child_key', input);
    }

    /**
     * Generates a hardened Hierarchical Deterministic Key path
     *
     * @param purposeOrPath the purpose (numeric) or path (e.g. m/44'/0'/1/3)
     * @param coin_type
     * @param account
     * @param change
     * @param address_index
     */
    public make_path (
        purposeOrPath?: number | string,
        coin_type?: number,
        account?: number,
        change?: number,
        address_index?: number
    ): string {
        if (typeof purposeOrPath === 'string') {
            return purposeOrPath.toLowerCase();
        }

        let output = 'm';

        if (typeof purposeOrPath !== 'undefined') {
            output += `/${purposeOrPath}'`;

            if (typeof coin_type !== 'undefined') {
                output += `/${coin_type}'`;

                if (typeof account !== 'undefined') {
                    output += `/${account}'`;

                    if (typeof change !== 'undefined') {
                        output += `/${change}'`;

                        if (typeof address_index !== 'undefined') {
                            output += `/${address_index}'`;
                        }
                    }
                }
            }
        }

        return output;
    }

    /**
     * Executes the method call using the underlying library
     *
     * @param method
     * @param argument
     * @private
     */
    private async execute<ResultType = string, ArgumentType = any> (
        method: string,
        argument?: ArgumentType
    ): Promise<ResultType> {
        const method_call: Library.CallTypes.Signature | undefined = (() => {
            if (typeof this.external_library[method] !== 'undefined') {
                return this.external_library[method];
            }

            if (!CryptoModule.runtime_configuration.library) {
                return;
            }

            if (typeof CryptoModule.runtime_configuration.library[method] !== 'undefined') {
                return CryptoModule.runtime_configuration.library[method];
            }

            return undefined;
        })();

        if (!method_call) {
            throw new Error(`0x01: Method Not Found. ${method}(${argument ? JSON.stringify(argument) : ''})`);
        }

        let result: string;

        if (argument) {
            result = await (method_call as Library.CallTypes.WithArguments)(JSON.stringify(argument));
        } else {
            result = await (method_call as Library.CallTypes.WithoutArguments)();
        }

        const json: ModuleResult<ResultType> = JSON.parse(result);

        if (json.error) {
            throw new Error(json.error_message ??
                `0x04: An unknown error occurred: ${method}(${argument ? JSON.stringify(argument) : ''})`);
        }

        return json.result;
    }
}
