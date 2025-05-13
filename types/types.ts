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

/**
 * Represents a Bulletproof proof
 */
export type crypto_bulletproof_t = {
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
export type crypto_bulletproof_plus_t = {
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
export type crypto_borromean_signature_t = {
    signatures: string[];
}

/**
 * Represents a CLSAG signature
 */
export type crypto_clsag_signature_t = {
    scalars: string[];
    challenge: string;
    commitment_image?: string;
    pseudo_commitment?: string;
}

/**
 * Represents a Triptych signature
 */
export type crypto_triptych_signature_t = {
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
export type crypto_entropy_t = {
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
export type key_pair_t = {
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
