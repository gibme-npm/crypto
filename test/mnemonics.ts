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

import Crypto, { crypto_seed_t, Language, LanguageName } from '../typescript';
import { before, describe, it } from 'mocha';
import assert from 'assert';

const seed_hex = 'f39ea2ac069128355a8d8f5b3803cb6220050249511595497cec53a533dfcf07';
const mnemonic_phrase = [
    'taxi', 'hand', 'sample',
    'camp', 'seek', 'talk',
    'prize', 'truly', 'blame',
    'grow', 'narrow', 'settle',
    'piano', 'project', 'spatial',
    'pretty', 'wrist', 'case',
    'moon', 'tennis', 'crack',
    'toy', 'chair', 'claim',
    'tool'
].join(' ');

const test_language = (crypto: Crypto, language: Language) => {
    const _language = LanguageName(language);

    describe(`${_language}`, async () => {
        let seed: crypto_seed_t;

        before(async () => {
            seed = await crypto.seed_recover(mnemonic_phrase, Language.ENGLISH);
        });

        it('Encode', async function () {
            const words = await crypto.mnemonics_encode(seed_hex, language);

            assert.notEqual(words, seed.mnemonic_phrase);

            seed = await crypto.seed_recover(words, language);

            assert.equal(seed.seed, seed_hex);
        });

        it('Decode', async function () {
            const result = await crypto.mnemonics_decode(seed.mnemonic_phrase.split(' '), language);

            assert.equal(result.seed, seed_hex);
        });

        it('Word Index & Checksum Index', async function () {
            const words = (() => {
                const partial = seed.mnemonic_phrase.split(' ').reverse();

                partial.shift();

                return partial.reverse();
            })();

            const word = (() => {
                const words = seed.mnemonic_phrase.split(' ');

                return words.pop() ?? '';
            })();

            const expected_index = await crypto.mnemonics_word_index(word, language);

            const index = await crypto.mnemonics_calculate_checksum_index(words, language);

            assert.equal(index, expected_index);
        });

        it('Word List', async function () {
            const words = await crypto.word_list(language);

            assert.equal(words.length, 2048);
        });

        it('Word List Trimmed', async function () {
            const words = await crypto.word_list_trimmed(language);

            assert.equal(words.length, 2048);
        });
    });
};

export default test_language;
