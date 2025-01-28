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

import { CryptoModule, ICryptoLibrary } from './index';
export * from './index';

export default class Crypto extends CryptoModule {
    /**
     * We cannot create a new instance using this method as we need to await the
     * loading of an underlying module, hence, we need to await the static
     * init() method on this class to receive an instance of the class
     *
     * @protected
     */
    // eslint-disable-next-line no-useless-constructor
    protected constructor () {
        super();
    }

    /**
     * Initializes a new instance of this class from an external library source
     *
     * Note: this method will attempt to load any other underlying cryptographic
     * library so it is imperative that the methods you wish to use are
     * properly supported by the underlying cryptographic library
     *
     * @param externalLibrary
     */
    public static async init (externalLibrary: Partial<ICryptoLibrary>): Promise<Crypto> {
        this.external_library = externalLibrary;

        return new Crypto();
    }
}

export { Crypto };
