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

import { Language, LibraryType, ModuleResult } from './types';

/**
 * Constructs a Module Result
 *
 * Note: This is typically only used by external cryptographic library calls
 * so that it mimics our underlying library call results
 *
 * The string returned should always be a raw type, whether it be
 * a string, a number, or an object as expected by the module.
 *
 * If you are using external libraries for the underlying cryptographic library,
 * it is highly recommended that you read the source code of this module
 * to make sure that you are returning a result of the proper structure.
 *
 * This method will `JSON.stringify()` whatever result you supply so that our
 * module understands it within it's private `execute()` method
 *
 * @param error
 * @param result
 * @param error_message
 */
export const make_module_result = <ResultType = string> (
    error: boolean,
    result: ResultType,
    error_message?: string
): string => {
    const output: ModuleResult<ResultType> = {
        error,
        result
    };

    if (error_message) {
        output.error_message = error_message;
    }

    return JSON.stringify(output);
};

/**
 * Tests if the supplied string is of hexadecimal form
 *
 * @param value
 * @ignore
 */
export const is_hex = (value: string): boolean => {
    return /^[0-9a-f]+$/i.test(value);
};

/**
 * Returns the library name from the specified library type
 *
 * @param type
 * @ignore
 */
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

/**
 * Returns the common language name for the specified language
 *
 * @param language
 * @ignore
 */
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
