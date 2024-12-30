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

#ifndef NAN_MODULE_H
#define NAN_MODULE_H

#include <crypto.h>
#include <utility>

struct generate_child_key_input final
{
    JSON_OBJECT_CONSTRUCTOR(generate_child_key_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        LOAD_STRING_FROM_JSON(seed);

        if (has_member(j, "path"))
        {
            LOAD_STRING_FROM_JSON(path);
        }

        if (has_member(j, "hmac_key"))
        {
            LOAD_STRING_FROM_JSON(hmac_key);
        }

        if (has_member(j, "purpose"))
        {
            LOAD_U32_FROM_JSON(purpose);

            has_purpose = true;
        }

        if (has_member(j, "coin_type"))
        {
            LOAD_U32_FROM_JSON(coin_type);

            has_coin_type = true;
        }

        if (has_member(j, "account"))
        {
            LOAD_U32_FROM_JSON(account);

            has_account = true;
        }

        if (has_member(j, "change"))
        {
            LOAD_U32_FROM_JSON(change);

            has_change = true;
        }

        if (has_member(j, "address_index"))
        {
            LOAD_U32_FROM_JSON(address_index);

            has_address_index = true;
        }
    }

    std::string seed, path;
    std::string hmac_key = "ed25519 seed";
    size_t purpose = 0, coin_type = 0, account = 0, change = 0, address_index = 0;
    bool has_purpose = false, has_coin_type = false, has_account = false, has_change = false, has_address_index = false;
};

struct generate_seed_input final
{
    JSON_OBJECT_CONSTRUCTOR(generate_seed_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (has_member(j, "entropy"))
        {
            LOAD_KEY_FROM_JSON(entropy);
        }

        if (has_member(j, "passphrase"))
        {
            LOAD_STRING_FROM_JSON(passphrase);
        }

        if (has_member(j, "hmac_key"))
        {
            LOAD_STRING_FROM_JSON(hmac_key);
        }
    }

    crypto_entropy_t entropy;
    std::string passphrase;
    std::string hmac_key = "ed25519 seed";
};

struct random_entropy_input final
{
    JSON_OBJECT_CONSTRUCTOR(random_entropy_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_STRING_FROM_JSON(entropy);

        if (has_member(j, "language"))
        {
            language = static_cast<Crypto::Mnemonics::Language::Language>(get_json_uint32_t(j, "language"));
        }

        if (has_member(j, "encode_timestamp"))
        {
            LOAD_BOOL_FROM_JSON(encode_timestamp);
        }

        if (has_member(j, "bits"))
        {
            LOAD_U32_FROM_JSON(bits);
        }
    }

    std::string entropy;
    Crypto::Mnemonics::Language::Language language = Crypto::Mnemonics::Language::Language::ENGLISH;
    uint32_t bits;
    bool encode_timestamp;
};

struct entropy_recover_input final
{
    JSON_OBJECT_CONSTRUCTOR(entropy_recover_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_STRING_FROM_JSON(input);

        if (has_member(j, "language"))
        {
            language = static_cast<Crypto::Mnemonics::Language::Language>(get_json_uint32_t(j, "language"));
        }
    }

    std::string input;
    Crypto::Mnemonics::Language::Language language = Crypto::Mnemonics::Language::Language::ENGLISH;
};

struct mnemonics_options final
{
    JSON_OBJECT_CONSTRUCTOR(mnemonics_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (has_member(j, "input"))
        {
            LOAD_STRING_FROM_JSON(input);
        }

        if (has_member(j, "entropy"))
        {
            LOAD_KEY_FROM_JSON(entropy);
        }

        if (has_member(j, "language"))
        {
            language = static_cast<Crypto::Mnemonics::Language::Language>(get_json_uint32_t(j, "language"));
        }
    }

    std::string input;
    crypto_entropy_t entropy;
    Crypto::Mnemonics::Language::Language language = Crypto::Mnemonics::Language::Language::ENGLISH;
};

struct sha3_slow_options final
{
    JSON_OBJECT_CONSTRUCTOR(sha3_slow_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_STRING_FROM_JSON(input);

        LOAD_U64_FROM_JSON(iterations);
    }

    std::string input;
    uint64_t iterations = 0;
};

struct argon2_options final
{
    JSON_OBJECT_CONSTRUCTOR(argon2_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_STRING_FROM_JSON(input);

        LOAD_U32_FROM_JSON(iterations);

        LOAD_U32_FROM_JSON(memory);

        LOAD_U32_FROM_JSON(threads);
    }

    std::string input;
    uint32_t iterations = 1;
    uint32_t memory = 256;
    uint32_t threads = 1;
};

struct entropy_recover_output final
{
    explicit entropy_recover_output(
        const crypto_entropy_t &value,
        const Crypto::Mnemonics::Language::Language &language):
        entropy(value)
    {
        timestamp = value.timestamp();
        mnemonic_phrase = value.to_mnemonic_phrase(language);
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEY_TO_JSON(entropy);

            U64_TO_JSON(timestamp);

            STRING_TO_JSON(mnemonic_phrase);
        }
        writer.EndObject();
    }

    crypto_entropy_t entropy;
    uint64_t timestamp;
    std::string mnemonic_phrase;
};

struct key_pair final
{
    key_pair(const crypto_public_key_t &public_key, const crypto_scalar_t &secret_key):
        public_key(public_key), secret_key(secret_key)
    {
    }

    key_pair(const crypto_public_key_t &public_key, const crypto_secret_key_t &_secret_key):
        public_key(public_key), private_key(_secret_key)
    {
        secret_key = private_key.scalar();
    }

    JSON_OBJECT_CONSTRUCTOR(key_pair, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(public_key);

        LOAD_KEY_FROM_JSON(secret_key);
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEY_TO_JSON(public_key);

            KEY_TO_JSON(secret_key);

            if (!private_key.empty())
            {
                KEY_TO_JSON(private_key);
            }
        }
        writer.EndObject();
    }

    crypto_public_key_t public_key;
    crypto_scalar_t secret_key;
    crypto_secret_key_t private_key;
};

struct entropy_spend_keys_options final
{
    JSON_OBJECT_CONSTRUCTOR(entropy_spend_keys_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(entropy);

        LOAD_U64_FROM_JSON(wallet_index)
    }

    crypto_entropy_t entropy;
    uint64_t wallet_index = 0;
};

struct generate_derivation_scalar_options final
{
    JSON_OBJECT_CONSTRUCTOR(generate_derivation_scalar_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(derivation);

        LOAD_U64_FROM_JSON(output_index);
    }

    crypto_derivation_t derivation;
    uint64_t output_index = 0;
};

struct derive_public_key_options final
{
    JSON_OBJECT_CONSTRUCTOR(derive_public_key_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(derivation_scalar);

        LOAD_KEY_FROM_JSON(public_key);
    }

    crypto_scalar_t derivation_scalar;
    crypto_public_key_t public_key;
};

struct derive_secret_key_options final
{
    JSON_OBJECT_CONSTRUCTOR(derive_secret_key_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(derivation_scalar);

        LOAD_KEY_FROM_JSON(secret_key);
    }

    crypto_scalar_t derivation_scalar;
    crypto_secret_key_t secret_key;
};

struct generate_key_image_options final
{
    JSON_OBJECT_CONSTRUCTOR(generate_key_image_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(public_ephemeral);

        LOAD_KEY_FROM_JSON(secret_ephemeral);
    }

    crypto_public_key_t public_ephemeral;
    crypto_scalar_t secret_ephemeral;
};

struct underive_public_key_options final
{
    JSON_OBJECT_CONSTRUCTOR(underive_public_key_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(derivation);

        LOAD_U64_FROM_JSON(output_index);

        LOAD_KEY_FROM_JSON(public_ephemeral);
    }

    crypto_derivation_t derivation;
    uint64_t output_index = 0;
    crypto_public_key_t public_ephemeral;
};

struct root_hash_from_branch_options final
{
    JSON_OBJECT_CONSTRUCTOR(root_hash_from_branch_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEYV_FROM_JSON(branches, crypto_hash_t);

        LOAD_U64_FROM_JSON(depth);

        LOAD_KEY_FROM_JSON(leaf);

        LOAD_U64_FROM_JSON(path);
    }

    std::vector<crypto_hash_t> branches;
    uint64_t depth = 0;
    crypto_hash_t leaf;
    uint64_t path = 0;
};

struct generate_signature_options final
{
    JSON_OBJECT_CONSTRUCTOR(generate_signature_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (has_member(j, "message"))
        {
            LOAD_STRING_FROM_JSON(message);
        }

        if (has_member(j, "message_digest"))
        {
            LOAD_KEY_FROM_JSON(message_digest);
        }

        if (has_member(j, "secret_key"))
        {
            LOAD_KEY_FROM_JSON(secret_key);
        }

        if (has_member(j, "public_key"))
        {
            LOAD_KEY_FROM_JSON(public_key);
        }

        if (has_member(j, "signature"))
        {
            LOAD_KEY_FROM_JSON(signature);
        }
    }

    std::string message;
    crypto_hash_t message_digest;
    crypto_scalar_t secret_key;
    crypto_public_key_t public_key;
    crypto_signature_t signature;
};

struct check_signature_options final
{
    JSON_OBJECT_CONSTRUCTOR(check_signature_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (has_member(j, "message"))
        {
            LOAD_STRING_FROM_JSON(message);
        }

        if (has_member(j, "message_digest"))
        {
            LOAD_KEY_FROM_JSON(message_digest);
        }

        LOAD_KEY_FROM_JSON(public_key);

        LOAD_KEY_FROM_JSON(signature);
    }

    std::string message;
    crypto_hash_t message_digest;
    crypto_public_key_t public_key;
    crypto_signature_t signature;
};

template<typename SignatureType> struct generate_ringsignature_options final
{
    JSON_OBJECT_CONSTRUCTOR(generate_ringsignature_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (has_member(j, "message_digest"))
        {
            LOAD_KEY_FROM_JSON(message_digest)
        }

        if (has_member(j, "secret_ephemeral"))
        {
            LOAD_KEY_FROM_JSON(secret_ephemeral)
        }

        if (has_member(j, "public_keys"))
        {
            LOAD_KEYV_FROM_JSON(public_keys, crypto_public_key_t)
        }

        if (has_member(j, "input_blinding_factor"))
        {
            LOAD_KEY_FROM_JSON(input_blinding_factor);
        }

        if (has_member(j, "public_commitments"))
        {
            LOAD_KEYV_FROM_JSON(public_commitments, crypto_pedersen_commitment_t);
        }

        if (has_member(j, "pseudo_blinding_factor"))
        {
            LOAD_KEY_FROM_JSON(pseudo_blinding_factor);
        }

        if (has_member(j, "pseudo_commitment"))
        {
            LOAD_KEY_FROM_JSON(pseudo_commitment);
        }

        if (has_member(j, "real_output_index"))
        {
            LOAD_U64_FROM_JSON(real_output_index);
        }

        if (has_member(j, "key_image"))
        {
            LOAD_KEY_FROM_JSON(key_image);
        }

        if (has_member(j, "signature"))
        {
            LOAD_KEY_FROM_JSON(signature);
        }

        if (has_member(j, "h"))
        {
            LOAD_KEYV_FROM_JSON(h, crypto_scalar_t);
        }

        if (has_member(j, "mu_P"))
        {
            LOAD_KEY_FROM_JSON(mu_P);
        }

        if (has_member(j, "xpow"))
        {
            LOAD_KEY_FROM_JSON(xpow);
        }
    }

    crypto_hash_t message_digest;
    crypto_scalar_t secret_ephemeral;
    std::vector<crypto_public_key_t> public_keys;
    uint64_t real_output_index = 0;
    crypto_key_image_t key_image;
    crypto_blinding_factor_t input_blinding_factor = Crypto::ZERO;
    std::vector<crypto_pedersen_commitment_t> public_commitments;
    crypto_blinding_factor_t pseudo_blinding_factor = Crypto::ZERO;
    crypto_pedersen_commitment_t pseudo_commitment = Crypto::Z;
    SignatureType signature;
    std::vector<crypto_scalar_t> h;
    crypto_scalar_t mu_P, xpow;
};

template<typename SignatureType> struct prepare_ringsignature_output final
{
    prepare_ringsignature_output(
        const SignatureType &signature,
        const std::vector<crypto_scalar_t> &h,
        crypto_scalar_t mu_P):
        signature(signature), h(h), mu_P(std::move(mu_P))
    {
    }

    prepare_ringsignature_output(const SignatureType &signature, crypto_scalar_t xpow):
        signature(signature), xpow(std::move(xpow))
    {
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEY_TO_JSON(signature);

            if (!h.empty())
            {
                KEYV_TO_JSON(h);
            }

            if (!mu_P.empty())
            {
                KEY_TO_JSON(mu_P);
            }

            if (!xpow.empty())
            {
                KEY_TO_JSON(xpow);
            }
        }
        writer.EndObject();
    }

    SignatureType signature;
    std::vector<crypto_scalar_t> h;
    crypto_scalar_t mu_P, xpow;
};

template<typename SignatureType> struct check_ringsignature_options final
{
    JSON_OBJECT_CONSTRUCTOR(check_ringsignature_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(message_digest);

        LOAD_KEY_FROM_JSON(key_image);

        LOAD_KEYV_FROM_JSON(public_keys, crypto_public_key_t);

        LOAD_KEY_FROM_JSON(signature);

        if (has_member(j, "commitments"))
        {
            LOAD_KEYV_FROM_JSON(commitments, crypto_pedersen_commitment_t);
        }
    }

    crypto_hash_t message_digest;
    crypto_key_image_t key_image;
    std::vector<crypto_public_key_t> public_keys;
    SignatureType signature;
    std::vector<crypto_pedersen_commitment_t> commitments;
};

struct prove_bulletproofs_options final
{
    JSON_OBJECT_CONSTRUCTOR(prove_bulletproofs_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (!has_member(j, "amounts"))
        {
            throw std::invalid_argument("amounts not found in JSON object");
        }

        amounts.clear();

        for (const auto &elem : get_json_array(j, "amounts"))
        {
            auto temp = get_json_uint64_t(elem);

            amounts.emplace_back(temp);
        }

        LOAD_KEYV_FROM_JSON(blinding_factors, crypto_blinding_factor_t);

        if (has_member(j, "N"))
        {
            N = get_json_uint64_t(j, "N");
        }
    }

    std::vector<uint64_t> amounts;
    std::vector<crypto_blinding_factor_t> blinding_factors;
    size_t N = 64;
};

template<typename ProofType> struct rangeproof_result final
{
    rangeproof_result() = default;

    rangeproof_result(const ProofType &proof, const std::vector<crypto_pedersen_commitment_t> &commitments):
        proof(proof), commitments(commitments)
    {
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEY_TO_JSON(proof);

            KEYV_TO_JSON(commitments);
        }
        writer.EndObject();
    }

    ProofType proof;
    std::vector<crypto_pedersen_commitment_t> commitments;
};

template<typename ProofType> struct verify_bulletproofs_options final
{
    JSON_OBJECT_CONSTRUCTOR(verify_bulletproofs_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(proof);

        LOAD_KEYV_FROM_JSON(commitments, crypto_pedersen_commitment_t);

        if (has_member(j, "N"))
        {
            N = get_json_uint64_t(j, "N");
        }
    }

    ProofType proof;
    std::vector<crypto_pedersen_commitment_t> commitments;
    size_t N = 64;
};

template<typename ProofType> struct verify_bulletproofs_batch_options final
{
    JSON_OBJECT_CONSTRUCTOR(verify_bulletproofs_batch_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEYV_FROM_JSON(proofs, ProofType);

        LOAD_KEYVV_FROM_JSON(commitments, crypto_pedersen_commitment_t);
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEYV_TO_JSON(proofs);

            KEYVV_TO_JSON(commitments);
        }
        writer.EndObject();
    }

    std::vector<ProofType> proofs;
    std::vector<std::vector<crypto_pedersen_commitment_t>> commitments;
    size_t N = 64;
};

struct check_commitments_parity_options final
{
    JSON_OBJECT_CONSTRUCTOR(check_commitments_parity_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEYV_FROM_JSON(pseudo_commitments, crypto_pedersen_commitment_t);

        LOAD_KEYV_FROM_JSON(output_commitments, crypto_pedersen_commitment_t);

        LOAD_U64_FROM_JSON(transaction_fee);
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEYV_TO_JSON(pseudo_commitments);

            KEYV_TO_JSON(output_commitments);

            U64_TO_JSON(transaction_fee);
        }
        writer.EndObject();
    }

    std::vector<crypto_pedersen_commitment_t> pseudo_commitments;
    std::vector<crypto_pedersen_commitment_t> output_commitments;
    uint64_t transaction_fee = 0;
};

struct generate_pedersen_commitment_options final
{
    JSON_OBJECT_CONSTRUCTOR(generate_pedersen_commitment_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(blinding_factor);

        LOAD_U64_FROM_JSON(amount);
    }

    crypto_blinding_factor_t blinding_factor;
    uint64_t amount = 0;
};

struct generate_pseudo_commitments_options final
{
    JSON_OBJECT_CONSTRUCTOR(generate_pseudo_commitments_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        if (!has_member(j, "amounts"))
        {
            throw std::invalid_argument("amounts not foind in JSON object");
        }

        amounts.clear();

        for (const auto &elem : get_json_array(j, "amounts"))
        {
            auto temp = get_json_uint64_t(elem);

            amounts.emplace_back(temp);
        }

        LOAD_KEYV_FROM_JSON(output_blinding_factors, crypto_blinding_factor_t);
    }

    std::vector<uint64_t> amounts;
    std::vector<crypto_blinding_factor_t> output_blinding_factors;
};

struct generate_pseudo_commitements_output final
{
    generate_pseudo_commitements_output(
        const std::vector<crypto_blinding_factor_t> &blinding_factors,
        const std::vector<crypto_pedersen_commitment_t> &commitments):
        blinding_factors(blinding_factors), commitments(commitments)
    {
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEYV_TO_JSON(blinding_factors);

            KEYV_TO_JSON(commitments);
        }
        writer.EndObject();
    }

    std::vector<crypto_blinding_factor_t> blinding_factors;
    std::vector<crypto_pedersen_commitment_t> commitments;
};

struct toggle_masked_amount_options final
{
    JSON_OBJECT_CONSTRUCTOR(toggle_masked_amount_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEY_FROM_JSON(amount_mask);

        if (!has_member(j, "amount"))
        {
            throw std::invalid_argument("amount not found in JSON object");
        }

        const auto &elem = get_json_value(j, "amount");

        if (elem.IsUint64())
        {
            const auto value = get_json_uint64_t(elem);

            amount = crypto_scalar_t(value);
        }
        else
        {
            LOAD_KEY_FROM_JSON(amount);
        }
    }

    crypto_scalar_t amount_mask;
    crypto_scalar_t amount;
};

struct address_decode_output final
{
    address_decode_output(
        const uint64_t prefix,
        const crypto_public_key_t &public_spend,
        const crypto_public_key_t &public_view):
        prefix(prefix), public_spend(public_spend), public_view(public_view)
    {
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            U64_TO_JSON(prefix);

            KEY_TO_JSON(public_spend);

            KEY_TO_JSON(public_view);
        }
        writer.EndObject();
    }

    uint64_t prefix = 0;
    crypto_public_key_t public_spend, public_view;
};

struct address_encode_input final
{
    JSON_OBJECT_CONSTRUCTOR(address_encode_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_U64_FROM_JSON(prefix);

        if (has_member(j, "public_key"))
        {
            LOAD_KEY_FROM_JSON(public_key);
        }

        if (has_member(j, "public_spend"))
        {
            LOAD_KEY_FROM_JSON(public_spend);
        }

        if (has_member(j, "public_view"))
        {
            LOAD_KEY_FROM_JSON(public_view);
        }
    }

    uint64_t prefix = 0;
    crypto_public_key_t public_key, public_spend, public_view;
};

struct check_audit_proof_input final
{
    JSON_OBJECT_CONSTRUCTOR(check_audit_proof_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEYV_FROM_JSON(public_ephemerals, crypto_public_key_t);

        LOAD_STRING_FROM_JSON(proof);
    }

    std::vector<crypto_public_key_t> public_ephemerals;
    std::string proof;
};

struct generate_keys_m_output final
{
    generate_keys_m_output(
        const std::vector<crypto_public_key_t> &public_keys,
        const std::vector<crypto_scalar_t> &secret_keys):
        public_keys(public_keys), secret_keys(secret_keys)
    {
    }

    JSON_TO_FUNC(toJSON)
    {
        writer.StartObject();
        {
            KEY_TO_JSON(public_keys);

            KEY_TO_JSON(secret_keys);
        }
        writer.EndObject();
    }

    crypto_point_vector_t public_keys;
    crypto_scalar_vector_t secret_keys;
};

struct aes_input_options final
{
    JSON_OBJECT_CONSTRUCTOR(aes_input_options, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_STRING_FROM_JSON(input);

        LOAD_STRING_FROM_JSON(password);

        if (has_member(j, "iterations"))
        {
            LOAD_U64_FROM_JSON(iterations);
        }
    }

    std::string input, password;
    uint64_t iterations = CRYPTO_PBKDF2_ITERATIONS;
};

template<typename Type> struct vector_input final
{
    JSON_OBJECT_CONSTRUCTOR(vector_input, fromJSON);

    JSON_FROM_FUNC(fromJSON)
    {
        JSON_OBJECT_OR_THROW();

        LOAD_KEYV_FROM_JSON(items, Type);
    }

    std::vector<Type> items;
};

#endif
