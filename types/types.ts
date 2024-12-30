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

/**
 * @ignore
 */
export interface ModuleResult<Type> {
    error: boolean;
    result: Type;
    error_message?: string;
}

/**
 * The type of the underlying cryptographic library
 */
export enum LibraryType {
    UNKNOWN,
    NODE,
    WASM,
    JS
}

/**
 * The type of the mnemonic phrase language
 *
 * Note: You will want to call the module `languages()` to get
 * the list of languages supported by the underlying cryptographic
 * module before attempting to use a particular language
 */
export enum Language {
    CHINESE_SIMPLIFIED,
    CHINESE_TRADITIONAL,
    CZECH,
    ENGLISH,
    FRENCH,
    ITALIAN,
    JAPANESE,
    KOREAN,
    PORTUGUESE,
    SPANISH
}

/**
 * Represents a Bulletproof proof
 */
export interface crypto_bulletproof_t {
    A: string;
    S: string;
    T1: string;
    T2: string;
    taux: string;
    mu: string;
    L: string[];
    R: string[];
    g: string;
    h: string;
    t: string;
}

/**
 * Represents a Bulletproof+ proof
 */
export interface crypto_bulletproof_plus_t {
    A: string;
    A1: string;
    B: string;
    r1: string;
    s1: string;
    d1: string;
    L: string[];
    R: string[];
}

/**
 * Represents a Borromean signature
 */
export interface crypto_borromean_signature_t {
    signatures: string[];
}

/**
 * Represents a CLSAG signature
 */
export interface crypto_clsag_signature_t {
    scalars: string[];
    challenge: string;
    commitment_image?: string;
    pseudo_commitment?: string;
}

/**
 * Represents a Triptych signature
 */
export interface crypto_triptych_signature_t {
    commitment_image: string;
    pseudo_commitment: string;
    A: string;
    B: string;
    C: string;
    D: string;
    X: string[];
    Y: string[];
    f: string[][];
    zA: string;
    zC: string;
    z: string;
}

/**
 * Represents cryptographic entropy
 */
export interface crypto_entropy_t {
    /**
     * The raw entropy encoded as a hexadecimal string
     */
    entropy: string;
    /**
     * The UNIX timestamp that the entropy was created (if properly stored within the `entropy`)
     */
    timestamp: number;
    /**
     * The mnemonic phrase that represents the `entropy`
     */
    mnemonic_phrase: string;
}

/**
 * Represents a public/secret key pair
 */
export interface key_pair_t {
    /**
     * The public key
     */
    public_key: string;
    /**
     * The secret key  (scalar)
     */
    secret_key: string;
    /**
     * The ED25519 private key per RFC-8032 (only returned when generating child keys)
     */
    private_key?: string;
}

/**
 * Contains types used when interacting with our underlying cryptographic library
 */
export namespace Library {
    /**
     * Defines the structure for when we interact with the generation of ring
     * signatures using our underlying cryptographic library
     */
    export interface GenerateRingSignature<SignatureType = any> {
        message_digest?: string;
        secret_ephemeral?: string;
        public_keys?: string[];
        input_blinding_factor?: string;
        public_commitments?: string[];
        pseudo_blinding_factor?: string;
        pseudo_commitment?: string;
        real_output_index?: number;
        key_image?: string;
        signature?: SignatureType;
        h?: string[];
        mu_P?: string;
        xpow?: string;
    }

    /**
     * Defines the structure for when we interact with the AES methods
     * in our underlying cryptographic library
     */
    export interface AES {
        input: string;
        password: string;
        iterations?: number;
    }

    /**
     * Defines the structure for when we interact with the checking of ring
     * signatures using our underlying cryptographic library
     */
    export interface CheckRingSignature<SignatureType> {
        message_digest: string;
        key_image: string;
        public_keys: string[];
        signature: SignatureType;
        commitments?: string[];
    }

    /**
     * Defines the Call types going into our underlying cryptographic library
     */
    export namespace CallTypes {
        export type WithArguments = (input: string) => Promise<string>;
        export type WithoutArguments = () => Promise<string>;
        export type Signature = WithArguments | WithoutArguments;
    }
}

/**
 * Defines the interface uses with our underlying cryptographic library
 * or an externally provided library
 */
export interface ICryptoLibrary {
    random_entropy: Library.CallTypes.WithoutArguments;
    random_hash: Library.CallTypes.WithoutArguments;
    random_hashes: Library.CallTypes.WithArguments;
    random_scalar: Library.CallTypes.WithoutArguments;
    random_scalars: Library.CallTypes.WithArguments;
    random_point: Library.CallTypes.WithoutArguments;
    random_points: Library.CallTypes.WithArguments;
    sha3: Library.CallTypes.WithArguments;
    sha3_slow: Library.CallTypes.WithArguments;
    argon2i: Library.CallTypes.WithArguments;
    argon2d: Library.CallTypes.WithArguments;
    argon2id: Library.CallTypes.WithArguments;
    entropy_recover: Library.CallTypes.WithArguments;
    generate_derivation: Library.CallTypes.WithArguments;
    generate_derivation_scalar: Library.CallTypes.WithArguments;
    derive_public_key: Library.CallTypes.WithArguments;
    derive_secret_key: Library.CallTypes.WithArguments;
    generate_key_image: Library.CallTypes.WithArguments;
    generate_key_image_v2: Library.CallTypes.WithArguments;
    generate_keys: Library.CallTypes.WithoutArguments;
    underive_public_key: Library.CallTypes.WithArguments;
    secret_key_to_public_key: Library.CallTypes.WithArguments;
    hash_to_point: Library.CallTypes.WithArguments;
    hash_to_scalar: Library.CallTypes.WithArguments;
    scalar_reduce: Library.CallTypes.WithArguments;
    tree_depth: Library.CallTypes.WithArguments;
    root_hash: Library.CallTypes.WithArguments;
    root_hash_from_branch: Library.CallTypes.WithArguments;
    tree_branch: Library.CallTypes.WithArguments;
    generate_signature: Library.CallTypes.WithArguments;
    prepare_signature: Library.CallTypes.WithArguments;
    complete_signature: Library.CallTypes.WithArguments;
    check_signature: Library.CallTypes.WithArguments;
    generate_borromean_signature: Library.CallTypes.WithArguments;
    prepare_borromean_signature: Library.CallTypes.WithArguments;
    complete_borromean_signature: Library.CallTypes.WithArguments;
    check_borromean_signature: Library.CallTypes.WithArguments;
    generate_clsag_signature: Library.CallTypes.WithArguments;
    prepare_clsag_signature: Library.CallTypes.WithArguments;
    complete_clsag_signature: Library.CallTypes.WithArguments;
    check_clsag_signature: Library.CallTypes.WithArguments;
    generate_triptych_signature: Library.CallTypes.WithArguments;
    prepare_triptych_signature: Library.CallTypes.WithArguments;
    complete_triptych_signature: Library.CallTypes.WithArguments;
    check_triptych_signature: Library.CallTypes.WithArguments;
    generate_bulletproof: Library.CallTypes.WithArguments;
    check_bulletproof: Library.CallTypes.WithArguments;
    check_bulletproof_batch: Library.CallTypes.WithArguments;
    generate_bulletproof_plus: Library.CallTypes.WithArguments;
    check_bulletproof_plus: Library.CallTypes.WithArguments;
    check_bulletproof_plus_batch: Library.CallTypes.WithArguments;
    check_commitment_parity: Library.CallTypes.WithArguments;
    generate_amount_mask: Library.CallTypes.WithArguments;
    generate_commitment_blinding_factor: Library.CallTypes.WithArguments;
    generate_pedersen_commitment: Library.CallTypes.WithArguments;
    generate_pseudo_commitments: Library.CallTypes.WithArguments;
    toggle_masked_amount: Library.CallTypes.WithArguments;
    base58_address_decode: Library.CallTypes.WithArguments;
    cn_base58_address_decode: Library.CallTypes.WithArguments;
    generate_outputs_proof: Library.CallTypes.WithArguments;
    check_outputs_proof: Library.CallTypes.WithArguments;
    base58_encode: Library.CallTypes.WithArguments;
    base58_encode_check: Library.CallTypes.WithArguments;
    base58_decode: Library.CallTypes.WithArguments;
    base58_decode_check: Library.CallTypes.WithArguments;
    cn_base58_encode: Library.CallTypes.WithArguments;
    cn_base58_encode_check: Library.CallTypes.WithArguments;
    cn_base58_decode: Library.CallTypes.WithArguments;
    cn_base58_decode_check: Library.CallTypes.WithArguments;
    check_scalar: Library.CallTypes.WithArguments;
    check_point: Library.CallTypes.WithArguments;
    generate_keys_m: Library.CallTypes.WithArguments;
    mnemonics_encode: Library.CallTypes.WithArguments;
    mnemonics_decode: Library.CallTypes.WithArguments;
    mnemonics_calculate_checksum_index: Library.CallTypes.WithArguments;
    mnemonics_word_index: Library.CallTypes.WithArguments;
    word_list: Library.CallTypes.WithoutArguments;
    word_list_trimmed: Library.CallTypes.WithoutArguments;
    calculate_base2_exponent: Library.CallTypes.WithArguments;
    aes_encrypt: Library.CallTypes.WithArguments;
    aes_decrypt: Library.CallTypes.WithArguments;
    generate_seed: Library.CallTypes.WithArguments;
    generate_child_key: Library.CallTypes.WithArguments;
    private_key_to_keys: Library.CallTypes.WithArguments;

    [key: string]: Library.CallTypes.Signature;
}

/** @ignore */
export interface ModuleSettings {
    library?: ICryptoLibrary;
    type: LibraryType;
}
