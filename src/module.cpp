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

#include <module.h>

#ifdef __NODE__
#include <nan.h>
#include <v8.h>
#endif

#ifdef __JAVASCRIPT__
#include <emscripten/bind.h>
#endif

#ifdef __NODE__
#define REGISTER_FUNC(name)               \
    Nan::Set(                             \
        target,                           \
        Nan::New(#name).ToLocalChecked(), \
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(name)).ToLocalChecked())
#define METHOD_RETURN_TYPE v8::Local<v8::Value>
#define MAKE_FUNC(name) void name(const Nan::FunctionCallbackInfo<v8::Value> &info)
#define MAKE_FUNC_NO_ARGS(name) MAKE_FUNC(name)
#define MAKE_RESULT(success, value) info.GetReturnValue().Set(prepare_result(success, value))
#define MAKE_ERROR(error) info.GetReturnValue().Set(prepare_result(false, error))
#define LOAD_INPUT() STR_TO_JSON(get_string(info), json)

inline std::string get_string(const Nan::FunctionCallbackInfo<v8::Value> &info, const uint8_t index = 0)
{
    std::string result = std::string();

    if (info.Length() >= index)
    {
        if (info[index]->IsString())
        {
            result = std::string(
                *Nan::Utf8String(info[index]->ToString(Nan::GetCurrentContext()).FromMaybe(v8::Local<v8::String>())));
        }
    }

    return result;
}

#endif

#ifdef __JAVASCRIPT__
#define REGISTER_FUNC(name) emscripten::function(#name, &name)
#define METHOD_RETURN_TYPE std::string
#define MAKE_FUNC(name) std::string name(const std::string &info)
#define MAKE_FUNC_NO_ARGS(name) std::string name()
#define MAKE_RESULT(success, value) return prepare_result(success, value)
#define MAKE_ERROR(error) return prepare_result(false, error)
#define LOAD_INPUT() STR_TO_JSON(info, json)
#endif

template<typename T = Serializable> inline METHOD_RETURN_TYPE prepare_result(const bool success, const T &value)
{
    JSON_INIT();

    writer.StartObject();
    {
        writer.Key("error");
        writer.Bool(!success);

        if (success)
        {
            writer.Key("result");
        }
        else
        {
            writer.Key("error_message");
        }
        value.toJSON(writer);
    }
    writer.EndObject();

    JSON_DUMP(result);

#ifdef __JAVASCRIPT__
    return result;
#endif
#ifdef __NODE__
    return Nan::New(result).ToLocalChecked();
#endif
}

template<> inline METHOD_RETURN_TYPE prepare_result<size_t>(const bool success, const size_t &value)
{
    JSON_INIT();

    writer.StartObject();
    {
        writer.Key("error");
        writer.Bool(!success);

        if (success)
        {
            writer.Key("result");
        }
        else
        {
            writer.Key("error_message");
        }
        writer.Uint64(value);
    }
    writer.EndObject();

    JSON_DUMP(result);

#ifdef __JAVASCRIPT__
    return result;
#endif
#ifdef __NODE__
    return Nan::New(result).ToLocalChecked();
#endif
}

template<> inline METHOD_RETURN_TYPE prepare_result<std::string>(const bool success, const std::string &value)
{
    JSON_INIT();

    writer.StartObject();
    {
        writer.Key("error");
        writer.Bool(!success);

        if (success)
        {
            writer.Key("result");
        }
        else
        {
            writer.Key("error_message");
        }
        writer.String(value);
    }
    writer.EndObject();

    JSON_DUMP(result);

#ifdef __JAVASCRIPT__
    return result;
#endif
#ifdef __NODE__
    return Nan::New(result).ToLocalChecked();
#endif
}

template<>
inline METHOD_RETURN_TYPE prepare_result<std::vector<Crypto::Mnemonics::Language::Language>>(
    const bool success,
    const std::vector<Crypto::Mnemonics::Language::Language> &values)
{
    JSON_INIT();

    writer.StartObject();
    {
        writer.Key("error");
        writer.Bool(!success);

        if (success)
        {
            writer.Key("result");
            writer.StartArray();
            {
                for (const auto &value : values)
                {
                    writer.Uint(value);
                }
            }
            writer.EndArray();
        }
        else
        {
            writer.Key("error_message");
            writer.String("An unknown error occurred");
        }
    }
    writer.EndObject();

    JSON_DUMP(result);

#ifdef __JAVASCRIPT__
    return result;
#endif
#ifdef __NODE__
    return Nan::New(result).ToLocalChecked();
#endif
}

template<> inline METHOD_RETURN_TYPE prepare_result<std::exception>(const bool success, const std::exception &value)
{
    return prepare_result(success, std::string(value.what()));
}

inline std::vector<unsigned char> try_load_hex_string(const std::string &input)
{
    try
    {
        const auto value = Serialization::from_hex(input);

        return value;
    }
    catch (const std::exception &)
    {
        return {input.begin(), input.end()};
    }
}

MAKE_FUNC(random_entropy)
{
    try
    {
        LOAD_INPUT()

        const auto input = random_entropy_input(json);

        crypto_entropy_t entropy;

        if (!input.entropy.empty())
        {
            const auto _entropy = try_load_hex_string(input.entropy);

            entropy = crypto_entropy_t::random(input.bits, _entropy, input.encode_timestamp);
        }
        else
        {
            entropy = crypto_entropy_t::random(input.bits, {}, input.encode_timestamp);
        }

        MAKE_RESULT(true, entropy_recover_output(entropy, input.language));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC_NO_ARGS(random_hash)
{
    MAKE_RESULT(true, crypto_hash_t::random());
}

MAKE_FUNC(random_hashes)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_uint64_t(json);

        const auto output = crypto_hash_t::random(input);

        MAKE_RESULT(true, crypto_hash_vector_t(output));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC_NO_ARGS(random_scalar)
{
    MAKE_RESULT(true, crypto_scalar_t::random());
}

MAKE_FUNC(random_scalars)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_uint64_t(json);

        const auto output = crypto_scalar_t ::random(input);

        MAKE_RESULT(true, crypto_scalar_vector_t(output));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC_NO_ARGS(random_point)
{
    MAKE_RESULT(true, crypto_public_key_t::random());
}

MAKE_FUNC(random_points)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_uint64_t(json);

        const auto output = crypto_public_key_t ::random(input);

        MAKE_RESULT(true, crypto_point_vector_t(output));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(sha256)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::sha256(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(sha384)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::sha384(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(sha512)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::sha512(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(sha3)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::sha3(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(sha3_slow)
{
    try
    {
        LOAD_INPUT()

        const auto input = sha3_slow_options(json);

        const auto output = crypto_hash_t::sha3_slow(try_load_hex_string(input.input), input.iterations);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(blake2b)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::blake2b(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(argon2i)
{
    try
    {
        LOAD_INPUT()

        const auto input = argon2_options(json);

        const auto output =
            crypto_hash_t::argon2i(try_load_hex_string(input.input), input.iterations, input.memory, input.threads);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(argon2d)
{
    try
    {
        LOAD_INPUT()

        const auto input = argon2_options(json);

        const auto output =
            crypto_hash_t::argon2d(try_load_hex_string(input.input), input.iterations, input.memory, input.threads);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(argon2id)
{
    try
    {
        LOAD_INPUT()

        const auto input = argon2_options(json);

        const auto output =
            crypto_hash_t::argon2id(try_load_hex_string(input.input), input.iterations, input.memory, input.threads);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(entropy_recover)
{
    try
    {
        LOAD_INPUT()

        const auto input = entropy_recover_input(json);

        const auto entropy = crypto_entropy_t::recover(input.input, input.language);

        MAKE_RESULT(true, entropy_recover_output(entropy, input.language));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_derivation)
{
    try
    {
        LOAD_INPUT()

        const auto input = key_pair(json);

        const auto output = Crypto::generate_key_derivation(input.public_key, input.secret_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_derivation_scalar)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_derivation_scalar_options(json);

        const auto output = Crypto::derivation_to_scalar(input.derivation, input.output_index);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(derive_public_key)
{
    try
    {
        LOAD_INPUT()

        const auto input = derive_public_key_options(json);

        const auto output = Crypto::derive_public_key(input.derivation_scalar, input.public_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(derive_secret_key)
{
    try
    {
        LOAD_INPUT()

        const auto input = derive_secret_key_options(json);

        const auto output = Crypto::derive_secret_key(input.derivation_scalar, input.secret_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_key_image)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_key_image_options(json);

        const auto output = Crypto::generate_key_image(input.public_ephemeral, input.secret_ephemeral);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_key_image_v2)
{
    try
    {
        LOAD_INPUT()

        const auto input = crypto_scalar_t(json);

        const auto output = Crypto::generate_key_image_v2(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC_NO_ARGS(generate_keys)
{
    const auto [public_key, secret_key] = Crypto::generate_keys();

    const auto output = key_pair(public_key, secret_key);

    MAKE_RESULT(true, output);
}

MAKE_FUNC(generate_keys_m)
{
    try
    {
        LOAD_INPUT()

        const auto count = get_json_uint64_t(json);

        const auto [public_keys, secret_keys] = Crypto::generate_keys_m(count);

        MAKE_RESULT(true, generate_keys_m_output(public_keys, secret_keys));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(underive_public_key)
{
    try
    {
        LOAD_INPUT()

        const auto input = underive_public_key_options(json);

        const auto output = Crypto::underive_public_key(input.derivation, input.output_index, input.public_ephemeral);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(secret_key_to_public_key)
{
    try
    {
        LOAD_INPUT()

        const auto input = crypto_scalar_t(json);

        MAKE_RESULT(true, input.point());
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(private_key_to_keys)
{
    try
    {
        LOAD_INPUT()

        const auto secret_key = crypto_secret_key_t(json);

        const auto output = key_pair(secret_key.point(), secret_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(hash_to_point)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::sha3(input).point();

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(hash_to_scalar)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = crypto_hash_t::sha3(input).scalar();

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(scalar_reduce)
{
    try
    {
        LOAD_INPUT()

        const auto input = crypto_scalar_t(json);

        MAKE_RESULT(true, input.reduce());
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(tree_depth)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_uint64_t(json);

        const auto output = Crypto::Merkle::tree_depth(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(root_hash)
{
    try
    {
        LOAD_INPUT()

        const auto input = vector_input<crypto_hash_t>(json);

        const auto output = Crypto::Merkle::root_hash(input.items);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(root_hash_from_branch)
{
    try
    {
        LOAD_INPUT()

        const auto input = root_hash_from_branch_options(json);

        const auto output = Crypto::Merkle::root_hash_from_branch(input.branches, input.depth, input.leaf, input.path);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(tree_branch)
{
    try
    {
        LOAD_INPUT()

        const auto input = vector_input<crypto_hash_t>(json);

        const auto output = Crypto::Merkle::tree_branch(input.items);

        MAKE_RESULT(true, crypto_hash_vector_t(output));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_rfc8032_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_signature_options(json);

        const auto message = try_load_hex_string(input.message);

        const auto output = Crypto::RFC8032::generate_signature(message.data(), message.size(), input.secret_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_rfc8032_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_signature_options(json);

        const auto message = try_load_hex_string(input.message);

        const auto success =
            Crypto::RFC8032::check_signature(message.data(), message.size(), input.public_key, input.signature);

        if (success)
        {
            MAKE_RESULT(success, input.signature);
        }
        else
        {
            MAKE_ERROR(std::string("Signature is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_signature_options(json);

        const auto output = Crypto::Signature::generate_signature(input.message_digest, input.secret_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(prepare_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_signature_options(json);

        const auto output = Crypto::Signature::prepare_signature(input.message_digest, input.public_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(complete_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_signature_options(json);

        const auto output = Crypto::Signature::complete_signature(input.secret_key, input.signature);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_signature_options(json);

        const auto success =
            Crypto::Signature::check_signature(input.message_digest, input.public_key, input.signature);

        if (success)
        {
            MAKE_RESULT(success, input.signature);
        }
        else
        {
            MAKE_ERROR(std::string("Signature is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_borromean_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_borromean_signature_t>(json);

        const auto [success, output] = Crypto::RingSignature::Borromean::generate_ring_signature(
            input.message_digest, input.secret_ephemeral, input.public_keys);

        if (success)
        {
            MAKE_RESULT(success, output);
        }
        else
        {
            MAKE_ERROR(std::string("Could not generate borromean ring signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(prepare_borromean_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_borromean_signature_t>(json);

        const auto [success, output] = Crypto::RingSignature::Borromean::prepare_ring_signature(
            input.message_digest, input.key_image, input.public_keys, input.real_output_index);

        if (success)
        {
            MAKE_RESULT(success, output);
        }
        else
        {
            MAKE_ERROR(std::string("Could not prepare borromean ring signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(complete_borromean_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_borromean_signature_t>(json);

        const auto [success, output] = Crypto::RingSignature::Borromean::complete_ring_signature(
            input.secret_ephemeral, input.real_output_index, input.signature);

        if (success)
        {
            MAKE_RESULT(success, output);
        }
        else
        {
            MAKE_ERROR(std::string("Could not complete borromean ring signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_borromean_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_ringsignature_options<crypto_borromean_signature_t>(json);

        const auto success = Crypto::RingSignature::Borromean::check_ring_signature(
            input.message_digest, input.key_image, input.public_keys, input.signature);

        if (success)
        {
            MAKE_RESULT(success, input.signature);
        }
        else
        {
            MAKE_ERROR(std::string("Signature is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_clsag_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_clsag_signature_t>(json);

        const auto [success, signature] = Crypto::RingSignature::CLSAG::generate_ring_signature(
            input.message_digest,
            input.secret_ephemeral,
            input.public_keys,
            input.input_blinding_factor,
            input.public_commitments,
            input.pseudo_blinding_factor,
            input.pseudo_commitment);

        if (success)
        {
            MAKE_RESULT(success, signature);
        }
        else
        {
            MAKE_ERROR(std::string("Could not generate CLSAG signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(prepare_clsag_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_clsag_signature_t>(json);

        const auto [success, output, h, mu_P] = Crypto::RingSignature::CLSAG::prepare_ring_signature(
            input.message_digest,
            input.key_image,
            input.public_keys,
            input.real_output_index,
            input.input_blinding_factor,
            input.public_commitments,
            input.pseudo_blinding_factor,
            input.pseudo_commitment);

        if (success)
        {
            MAKE_RESULT(success, prepare_ringsignature_output<crypto_clsag_signature_t>(output, h, mu_P));
        }
        else
        {
            MAKE_ERROR(std::string("Could not prepare CLSAG signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(complete_clsag_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_clsag_signature_t>(json);

        const auto [success, output] = Crypto::RingSignature::CLSAG::complete_ring_signature(
            input.secret_ephemeral, input.real_output_index, input.signature, input.h, input.mu_P);

        if (success)
        {
            MAKE_RESULT(success, output);
        }
        else
        {
            MAKE_ERROR(std::string("Could not complete CLSAG signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_clsag_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_ringsignature_options<crypto_clsag_signature_t>(json);

        const auto success = Crypto::RingSignature::CLSAG::check_ring_signature(
            input.message_digest, input.key_image, input.public_keys, input.signature, input.commitments);

        if (success)
        {
            MAKE_RESULT(success, input.signature);
        }
        else
        {
            MAKE_ERROR(std::string("Signature is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_triptych_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_triptych_signature_t>(json);

        const auto [success, signature] = Crypto::RingSignature::Triptych::generate_ring_signature(
            input.message_digest,
            input.secret_ephemeral,
            input.public_keys,
            input.input_blinding_factor,
            input.public_commitments,
            input.pseudo_blinding_factor,
            input.pseudo_commitment);

        if (success)
        {
            MAKE_RESULT(success, signature);
        }
        else
        {
            MAKE_ERROR(std::string("Could not generate Triptych signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(prepare_triptych_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_triptych_signature_t>(json);

        const auto [success, output, xpow] = Crypto::RingSignature::Triptych::prepare_ring_signature(
            input.message_digest,
            input.key_image,
            input.public_keys,
            input.real_output_index,
            input.input_blinding_factor,
            input.public_commitments,
            input.pseudo_blinding_factor,
            input.pseudo_commitment);

        if (success)
        {
            MAKE_RESULT(success, prepare_ringsignature_output<crypto_triptych_signature_t>(output, xpow));
        }
        else
        {
            MAKE_ERROR(std::string("Could not prepare Triptych signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(complete_triptych_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_ringsignature_options<crypto_triptych_signature_t>(json);

        const auto [success, output] = Crypto::RingSignature::Triptych::complete_ring_signature(
            input.secret_ephemeral, input.signature, input.xpow);

        if (success)
        {
            MAKE_RESULT(success, output);
        }
        else
        {
            MAKE_ERROR(std::string("Could not complete Triptych signature"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_triptych_signature)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_ringsignature_options<crypto_triptych_signature_t>(json);

        const auto success = Crypto::RingSignature::Triptych::check_ring_signature(
            input.message_digest, input.key_image, input.public_keys, input.signature, input.commitments);

        if (success)
        {
            MAKE_RESULT(success, input.signature);
        }
        else
        {
            MAKE_ERROR(std::string("Signature is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_bulletproof)
{
    try
    {
        LOAD_INPUT()

        const auto input = prove_bulletproofs_options(json);

        const auto [proof, commitments] =
            Crypto::RangeProofs::Bulletproofs::prove(input.amounts, input.blinding_factors, input.N);

        MAKE_RESULT(true, rangeproof_result<crypto_bulletproof_t>(proof, commitments));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_bulletproof)
{
    try
    {
        LOAD_INPUT()

        const auto input = verify_bulletproofs_options<crypto_bulletproof_t>(json);

        const auto success = Crypto::RangeProofs::Bulletproofs::verify(input.proof, input.commitments, input.N);

        if (success)
        {
            MAKE_RESULT(success, input.proof);
        }
        else
        {
            MAKE_ERROR(std::string("Proof is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_bulletproof_batch)
{
    try
    {
        LOAD_INPUT()

        const auto input = verify_bulletproofs_batch_options<crypto_bulletproof_t>(json);

        const auto success = Crypto::RangeProofs::Bulletproofs::verify(input.proofs, input.commitments, input.N);

        if (success)
        {
            MAKE_RESULT(success, input);
        }
        else
        {
            MAKE_ERROR(std::string("Proofs are invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_bulletproof_plus)
{
    try
    {
        LOAD_INPUT()

        const auto input = prove_bulletproofs_options(json);

        const auto [proof, commitments] =
            Crypto::RangeProofs::BulletproofsPlus::prove(input.amounts, input.blinding_factors, input.N);

        MAKE_RESULT(true, rangeproof_result<crypto_bulletproof_plus_t>(proof, commitments));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_bulletproof_plus)
{
    try
    {
        LOAD_INPUT()

        const auto input = verify_bulletproofs_options<crypto_bulletproof_plus_t>(json);

        const auto success = Crypto::RangeProofs::BulletproofsPlus::verify(input.proof, input.commitments, input.N);

        if (success)
        {
            MAKE_RESULT(success, input.proof);
        }
        else
        {
            MAKE_ERROR(std::string("Proof is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_bulletproof_plus_batch)
{
    try
    {
        LOAD_INPUT()

        const auto input = verify_bulletproofs_batch_options<crypto_bulletproof_plus_t>(json);

        const auto success = Crypto::RangeProofs::BulletproofsPlus::verify(input.proofs, input.commitments, input.N);

        if (success)
        {
            MAKE_RESULT(success, input);
        }
        else
        {
            MAKE_ERROR(std::string("Proofs are invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_commitments_parity)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_commitments_parity_options(json);

        const auto success = Crypto::RingCT::check_commitments_parity(
            input.pseudo_commitments, input.output_commitments, input.transaction_fee);

        if (success)
        {
            MAKE_RESULT(success, input);
        }
        else
        {
            MAKE_ERROR(std::string("Commitments do not have parity"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_amount_mask)
{
    try
    {
        LOAD_INPUT()

        const auto input = crypto_scalar_t(json);

        const auto output = Crypto::RingCT::generate_amount_mask(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_commitment_blinding_factor)
{
    try
    {
        LOAD_INPUT()

        const auto input = crypto_scalar_t(json);

        const auto output = Crypto::RingCT::generate_commitment_blinding_factor(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_pedersen_commitment)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_pedersen_commitment_options(json);

        const auto output = Crypto::RingCT::generate_pedersen_commitment(input.blinding_factor, input.amount);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_pseudo_commitments)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_pseudo_commitments_options(json);

        const auto [blinding_factors, commitments] =
            Crypto::RingCT::generate_pseudo_commitments(input.amounts, input.output_blinding_factors);

        MAKE_RESULT(true, generate_pseudo_commitements_output(blinding_factors, commitments));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(toggle_masked_amount)
{
    try
    {
        LOAD_INPUT()

        const auto input = toggle_masked_amount_options(json);

        const auto output = Crypto::RingCT::toggle_masked_amount(input.amount_mask, input.amount);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(base58_address_decode)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto [success, prefix, public_spend, public_view] = Crypto::Address::Base58::decode(input);

        if (success)
        {
            MAKE_RESULT(success, address_decode_output(prefix, public_spend, public_view));
        }
        else
        {
            MAKE_ERROR(std::string("Could not decode address"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(cn_base58_address_decode)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto [success, prefix, public_spend, public_view] = Crypto::Address::CNBase58::decode(input);

        if (success)
        {
            MAKE_RESULT(success, address_decode_output(prefix, public_spend, public_view));
        }
        else
        {
            MAKE_ERROR(std::string("Could not decode address"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(base58_address_encode)
{
    try
    {
        LOAD_INPUT()

        const auto input = address_encode_input(json);

        std::string output = std::string();

        if (!input.public_key.empty())
        {
            output = Crypto::Address::Base58::encode(input.prefix, input.public_key);
        }
        else
        {
            output = Crypto::Address::Base58::encode(input.prefix, input.public_spend, input.public_view);
        }

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(cn_base58_address_encode)
{
    try
    {
        LOAD_INPUT()

        const auto input = address_encode_input(json);

        std::string output = std::string();

        if (!input.public_key.empty())
        {
            output = Crypto::Address::CNBase58::encode(input.prefix, input.public_key);
        }
        else
        {
            output = Crypto::Address::CNBase58::encode(input.prefix, input.public_spend, input.public_view);
        }

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_outputs_proof)
{
    try
    {
        LOAD_INPUT()

        const auto input = check_audit_proof_input(json);

        const auto [success, key_images] = Crypto::Audit::check_outputs_proof(input.public_ephemerals, input.proof);

        if (success)
        {
            MAKE_RESULT(success, crypto_point_vector_t(key_images));
        }
        else
        {
            MAKE_ERROR(std::string("Proof is invalid"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_outputs_proof)
{
    try
    {
        LOAD_INPUT()

        const auto input = vector_input<crypto_scalar_t>(json);

        const auto [success, proof] = Crypto::Audit::generate_outputs_proof(input.items);

        if (success)
        {
            MAKE_RESULT(success, proof);
        }
        else
        {
            MAKE_ERROR(std::string("Could not generate outputs proof"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(base58_encode)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = Crypto::Base58::encode(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(base58_encode_check)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = Crypto::Base58::encode_check(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(base58_decode)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto [success, output] = Crypto::Base58::decode(input);

        if (success)
        {
            MAKE_RESULT(success, output.to_string());
        }
        else
        {
            MAKE_ERROR(std::string("Could not decode Base58 string"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(base58_decode_check)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto [success, output] = Crypto::Base58::decode_check(input);

        if (success)
        {
            MAKE_RESULT(success, output.to_string());
        }
        else
        {
            MAKE_ERROR(std::string("Could not decode Base58 string"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(cn_base58_encode)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = Crypto::CNBase58::encode(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(cn_base58_encode_check)
{
    try
    {
        LOAD_INPUT()

        const auto input = try_load_hex_string(get_json_string(json));

        const auto output = Crypto::CNBase58::encode_check(input);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(cn_base58_decode)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto [success, output] = Crypto::CNBase58::decode(input);

        if (success)
        {
            MAKE_RESULT(success, output.to_string());
        }
        else
        {
            MAKE_ERROR(std::string("Could not decode CryptoNote Base58 string"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(cn_base58_decode_check)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto [success, output] = Crypto::CNBase58::decode_check(input);

        if (success)
        {
            MAKE_RESULT(success, output.to_string());
        }
        else
        {
            MAKE_ERROR(std::string("Could not decode CryptoNote Base58 string"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_scalar)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto output = Crypto::check_scalar(input);

        MAKE_RESULT(output, input);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(check_point)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_string(json);

        const auto output = Crypto::check_point(input);

        MAKE_RESULT(output, input);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(mnemonics_encode)
{
    try
    {
        LOAD_INPUT()

        const auto input = mnemonics_options(json);

        const auto output = input.entropy.to_mnemonic_phrase(input.language);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(mnemonics_decode)
{
    try
    {
        LOAD_INPUT()

        const auto input = mnemonics_options(json);

        const auto output = crypto_entropy_t::recover(input.input, input.language);

        MAKE_RESULT(true, entropy_recover_output(output, input.language));
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(mnemonics_word_index)
{
    try
    {
        LOAD_INPUT()

        const auto input = mnemonics_options(json);

        const auto output = Crypto::Mnemonics::word_index(input.input, input.language);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(word_list)
{
    try
    {
        LOAD_INPUT()

        const auto input = mnemonics_options(json);

        const auto output = Serialization::str_join(Crypto::Mnemonics::word_list(input.language));

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(word_list_trimmed)
{
    try
    {
        LOAD_INPUT()

        const auto input = mnemonics_options(json);

        const auto output = Serialization::str_join(Crypto::Mnemonics::word_list_trimmed(input.language));

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(calculate_base2_exponent)
{
    try
    {
        LOAD_INPUT()

        const auto input = get_json_uint64_t(json);

        const auto [success, output] = Crypto::calculate_base2_exponent(input);

        if (success)
        {
            MAKE_RESULT(success, output);
        }
        else
        {
            MAKE_ERROR(std::string("Could not calculate base 2 exponent"));
        }
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(aes_encrypt)
{
    try
    {
        LOAD_INPUT()

        const auto input = aes_input_options(json);

        const auto output = Crypto::AES::encrypt(input.input, input.password, input.iterations);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(aes_decrypt)
{
    try
    {
        LOAD_INPUT()

        const auto input = aes_input_options(json);

        const auto output = Crypto::AES::decrypt(input.input, input.password, input.iterations);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC_NO_ARGS(languages)
{
    const auto output = Crypto::Mnemonics::languages();

    MAKE_RESULT(true, output);
}

MAKE_FUNC(generate_seed)
{
    try
    {
        LOAD_INPUT()

        const auto input = generate_seed_input(json);

        const auto seed = crypto_seed_t(input.entropy, input.passphrase, input.hmac_key);

        MAKE_RESULT(true, seed.to_string());
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

MAKE_FUNC(generate_child_key)
{
    try
    {
        LOAD_INPUT();

        const auto input = generate_child_key_input(json);

        const auto raw_bytes = try_load_hex_string(input.seed);

        const auto seed = crypto_seed_t(raw_bytes, input.hmac_key);

        crypto_hd_key_t key;

        if (!input.path.empty())
        {
            key = seed.generate_child_key(input.path);
        }
        else if (
            input.has_purpose && input.has_coin_type && input.has_account && input.has_change
            && input.has_address_index)
        {
            key = seed.generate_child_key(
                input.purpose, input.coin_type, input.account, input.change, input.address_index);
        }
        else if (input.has_purpose && input.has_coin_type && input.has_account && input.has_change)
        {
            key = seed.generate_child_key(input.purpose, input.coin_type, input.account, input.change);
        }
        else if (input.has_purpose && input.has_coin_type && input.has_account)
        {
            key = seed.generate_child_key(input.purpose, input.coin_type, input.account);
        }
        else if (input.has_purpose && input.has_coin_type)
        {
            key = seed.generate_child_key(input.purpose, input.coin_type);
        }
        else if (input.has_purpose)
        {
            key = seed.generate_child_key(input.purpose);
        }
        else
        {
            key = seed.generate_child_key();
        }

        const auto [public_key, secret_key] = key.keys();

        const auto output = key_pair(public_key, secret_key);

        MAKE_RESULT(true, output);
    }
    catch (const std::exception &error)
    {
        MAKE_ERROR(error);
    }
}

#ifdef __NODE__
NAN_MODULE_INIT(InitModule)
#endif
#ifdef __JAVASCRIPT__
EMSCRIPTEN_BINDINGS(cryptomodule)
#endif
{
    REGISTER_FUNC(random_entropy);

    REGISTER_FUNC(random_hash);

    REGISTER_FUNC(random_hashes);

    REGISTER_FUNC(random_scalar);

    REGISTER_FUNC(random_scalars);

    REGISTER_FUNC(random_point);

    REGISTER_FUNC(random_points);

    REGISTER_FUNC(sha256);

    REGISTER_FUNC(sha384);

    REGISTER_FUNC(sha512);

    REGISTER_FUNC(sha3);

    REGISTER_FUNC(sha3_slow);

    REGISTER_FUNC(blake2b);

    REGISTER_FUNC(argon2i);

    REGISTER_FUNC(argon2d);

    REGISTER_FUNC(argon2id);

    REGISTER_FUNC(entropy_recover);

    REGISTER_FUNC(generate_derivation);

    REGISTER_FUNC(generate_derivation_scalar);

    REGISTER_FUNC(derive_public_key);

    REGISTER_FUNC(derive_secret_key);

    REGISTER_FUNC(generate_key_image);

    REGISTER_FUNC(generate_key_image_v2);

    REGISTER_FUNC(generate_keys);

    REGISTER_FUNC(generate_keys_m);

    REGISTER_FUNC(underive_public_key);

    REGISTER_FUNC(secret_key_to_public_key);

    REGISTER_FUNC(private_key_to_keys);

    REGISTER_FUNC(hash_to_point);

    REGISTER_FUNC(hash_to_scalar);

    REGISTER_FUNC(tree_depth);

    REGISTER_FUNC(root_hash);

    REGISTER_FUNC(root_hash_from_branch);

    REGISTER_FUNC(tree_branch);

    REGISTER_FUNC(generate_rfc8032_signature);

    REGISTER_FUNC(check_rfc8032_signature);

    REGISTER_FUNC(generate_signature);

    REGISTER_FUNC(prepare_signature);

    REGISTER_FUNC(complete_signature);

    REGISTER_FUNC(check_signature);

    REGISTER_FUNC(generate_borromean_signature);

    REGISTER_FUNC(prepare_borromean_signature);

    REGISTER_FUNC(complete_borromean_signature);

    REGISTER_FUNC(check_borromean_signature);

    REGISTER_FUNC(generate_clsag_signature);

    REGISTER_FUNC(prepare_clsag_signature);

    REGISTER_FUNC(complete_clsag_signature);

    REGISTER_FUNC(check_clsag_signature);

    REGISTER_FUNC(generate_triptych_signature);

    REGISTER_FUNC(prepare_triptych_signature);

    REGISTER_FUNC(complete_triptych_signature);

    REGISTER_FUNC(check_triptych_signature);

    REGISTER_FUNC(generate_bulletproof);

    REGISTER_FUNC(check_bulletproof);

    REGISTER_FUNC(check_bulletproof_batch);

    REGISTER_FUNC(generate_bulletproof_plus);

    REGISTER_FUNC(check_bulletproof_plus);

    REGISTER_FUNC(check_bulletproof_plus_batch);

    REGISTER_FUNC(check_commitments_parity);

    REGISTER_FUNC(generate_amount_mask);

    REGISTER_FUNC(generate_commitment_blinding_factor);

    REGISTER_FUNC(generate_pedersen_commitment);

    REGISTER_FUNC(generate_pseudo_commitments);

    REGISTER_FUNC(toggle_masked_amount);

    REGISTER_FUNC(base58_address_decode);

    REGISTER_FUNC(cn_base58_address_decode);

    REGISTER_FUNC(base58_address_encode);

    REGISTER_FUNC(cn_base58_address_encode);

    REGISTER_FUNC(generate_outputs_proof);

    REGISTER_FUNC(check_outputs_proof);

    REGISTER_FUNC(base58_encode);

    REGISTER_FUNC(base58_encode_check);

    REGISTER_FUNC(base58_decode);

    REGISTER_FUNC(base58_decode_check);

    REGISTER_FUNC(cn_base58_encode);

    REGISTER_FUNC(cn_base58_encode_check);

    REGISTER_FUNC(cn_base58_decode);

    REGISTER_FUNC(cn_base58_decode_check);

    REGISTER_FUNC(check_scalar);

    REGISTER_FUNC(check_point);

    REGISTER_FUNC(mnemonics_encode);

    REGISTER_FUNC(mnemonics_decode);

    REGISTER_FUNC(mnemonics_word_index);

    REGISTER_FUNC(word_list);

    REGISTER_FUNC(word_list_trimmed);

    REGISTER_FUNC(calculate_base2_exponent);

    REGISTER_FUNC(aes_encrypt);

    REGISTER_FUNC(aes_decrypt);

    REGISTER_FUNC(scalar_reduce);

    REGISTER_FUNC(languages);

    REGISTER_FUNC(generate_seed);

    REGISTER_FUNC(generate_child_key);
}

#ifdef __NODE__
NODE_MODULE(cryptomodule, InitModule)
#endif
