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

export interface ModuleResult<Type> {
    error: boolean;
    result: Type;
    error_message?: string;
}

export enum LibraryType {
    UNKNOWN,
    NODE,
    WASM,
    JS
}

export const LibraryTypeName = (type: LibraryType): string => {
    switch (type) {
        case LibraryType.NODE:
            return 'Node C++ Addon';
        case LibraryType.WASM:
            return 'WASM.js Library';
        case LibraryType.JS:
            return 'Javascript asm.js (slow)';
        default:
            return 'unknown';
    }
};

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

export const LanguageName = (language: Language): string => {
    switch (language) {
        case Language.CHINESE_SIMPLIFIED:
            return 'Chinese (simplified)';
        case Language.CHINESE_TRADITIONAL:
            return 'Chinese (traditional)';
        case Language.CZECH:
            return 'Czech';
        case Language.ENGLISH:
            return 'English';
        case Language.FRENCH:
            return 'French';
        case Language.ITALIAN:
            return 'Italian';
        case Language.JAPANESE:
            return 'Japanese';
        case Language.KOREAN:
            return 'Korean';
        case Language.PORTUGUESE:
            return 'Portuguese';
        case Language.SPANISH:
            return 'Spanish';
        default:
            return 'Unknown';
    }
};

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

export interface crypto_seed_t {
    seed: string;
    timestamp: number;
    mnemonic_phrase: string;
}

export interface key_pair_t {
    public_key: string;
    secret_key: string;
}

export interface GenerateRingSignatureInput<SignatureType = any> {
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

export interface AESInput {
    input: string;
    password: string;
    iterations?: number;
}

export interface CheckRingSignatureInput<SignatureType> {
    message_digest: string;
    key_image: string;
    public_keys: string[];
    signature: SignatureType;
    commitments?: string[];
}

export type CallWithArguments = (input: string) => Promise<string>;
export type CallWithoutArguments = () => Promise<string>;
export type CallSignature = CallWithArguments | CallWithoutArguments;

export interface ExternalModuleInterface {
    random_seed: CallWithoutArguments;
    random_hash: CallWithoutArguments;
    random_hashes: CallWithArguments;
    random_scalar: CallWithoutArguments;
    random_scalars: CallWithArguments;
    random_point: CallWithoutArguments;
    random_points: CallWithArguments;
    sha3: CallWithArguments;
    sha3_slow: CallWithArguments;
    argon2i: CallWithArguments;
    argon2d: CallWithArguments;
    argon2id: CallWithArguments;
    seed_recover: CallWithArguments;
    seed_view_keys: CallWithArguments;
    seed_spend_keys: CallWithArguments;
    generate_derivation: CallWithArguments;
    generate_derivation_scalar: CallWithArguments;
    derive_public_key: CallWithArguments;
    derive_secret_key: CallWithArguments;
    generate_key_image: CallWithArguments;
    generate_key_image_v2: CallWithArguments;
    generate_keys: CallWithoutArguments;
    underive_public_key: CallWithArguments;
    secret_key_to_public_key: CallWithArguments;
    hash_to_point: CallWithArguments;
    hash_to_scalar: CallWithArguments;
    scalar_reduce: CallWithArguments;
    tree_depth: CallWithArguments;
    root_hash: CallWithArguments;
    root_hash_from_branch: CallWithArguments;
    tree_branch: CallWithArguments;
    generate_signature: CallWithArguments;
    prepare_signature: CallWithArguments;
    complete_signature: CallWithArguments;
    check_signature: CallWithArguments;
    generate_borromean_signature: CallWithArguments;
    prepare_borromean_signature: CallWithArguments;
    complete_borromean_signature: CallWithArguments;
    check_borromean_signature: CallWithArguments;
    generate_clsag_signature: CallWithArguments;
    prepare_clsag_signature: CallWithArguments;
    complete_clsag_signature: CallWithArguments;
    check_clsag_signature: CallWithArguments;
    generate_triptych_signature: CallWithArguments;
    prepare_triptych_signature: CallWithArguments;
    complete_triptych_signature: CallWithArguments;
    check_triptych_signature: CallWithArguments;
    generate_bulletproof: CallWithArguments;
    check_bulletproof: CallWithArguments;
    check_bulletproof_batch: CallWithArguments;
    generate_bulletproof_plus: CallWithArguments;
    check_bulletproof_plus: CallWithArguments;
    check_bulletproof_plus_batch: CallWithArguments;
    check_commitment_parity: CallWithArguments;
    generate_amount_mask: CallWithArguments;
    generate_commitment_blinding_factor: CallWithArguments;
    generate_pedersen_commitment: CallWithArguments;
    generate_pseudo_commitments: CallWithArguments;
    toggle_masked_amount: CallWithArguments;
    base58_address_decode: CallWithArguments;
    cn_base58_address_decode: CallWithArguments;
    generate_outputs_proof: CallWithArguments;
    check_outputs_proof: CallWithArguments;
    base58_encode: CallWithArguments;
    base58_encode_check: CallWithArguments;
    base58_decode: CallWithArguments;
    base58_decode_check: CallWithArguments;
    cn_base58_encode: CallWithArguments;
    cn_base58_encode_check: CallWithArguments;
    cn_base58_decode: CallWithArguments;
    cn_base58_decode_check: CallWithArguments;
    check_scalar: CallWithArguments;
    check_point: CallWithArguments;
    generate_keys_m: CallWithArguments;
    mnemonics_encode: CallWithArguments;
    mnemonics_decode: CallWithArguments;
    mnemonics_calculate_checksum_index: CallWithArguments;
    mnemonics_word_index: CallWithArguments;
    word_list: CallWithoutArguments;
    word_list_trimmed: CallWithoutArguments;
    calculate_base2_exponent: CallWithArguments;
    aes_encrypt: CallWithArguments;
    aes_decrypt: CallWithArguments;

    [key: string]: CallSignature;
}

export interface ModuleSettings {
    library?: ExternalModuleInterface;
    type: LibraryType;
}
