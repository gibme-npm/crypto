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

interface IUint256 {
    value: bigint;
    toString(littleEndian?: boolean): string;
}

interface IUint256Interface {
    (value: number | bigint): IUint256;
}

interface IUint256Static extends IUint256Interface {
    from(value: string, littleEndian?: boolean): IUint256;
}

/**
 * A very simple uint256 type for the expressed purpose of working
 * with our underlying cryptographic library
 *
 * @param value
 * @ignore
 */
const library: IUint256Interface = (value: number | bigint): IUint256 => {
    value = typeof value === 'number' ? BigInt(value) : value;

    return {
        value,
        toString: (littleEndian = true): string => {
            const buffer = new ArrayBuffer(32);
            new DataView(buffer).setBigUint64(0, value, littleEndian);
            let hex = '';
            new Uint8Array(buffer).forEach(byte => {
                hex += byte.toString(16).padStart(2, '0');
            });
            return hex;
        }
    };
};

/**
 * Loads a uint256 from a hexadecimal string value
 *
 * @param value
 * @param littleEndian
 * @ignore
 */
(library as any).from = (value: string, littleEndian = true) => {
    if (!/^[0-9a-f]+$/i.test(value)) throw new Error('Not a hexadecimal string');
    const hex_bytes: string[] = value.match(/.{1,2}/g) || [];
    if (hex_bytes.length !== 32) throw new Error('Invalid hexadecimal length');
    const array = Uint8Array.from(hex_bytes.map(byte => `0x${byte}`) as any);
    const int = new DataView(array.buffer).getBigUint64(0, littleEndian);
    return library(int);
};

/** @ignore */
export const uint256 = library as IUint256Static;
