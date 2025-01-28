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

import { CryptoModule, ICryptoLibrary, LibraryType } from '../../types';
import { version } from './version';
export * from '../../types';

declare global {
    interface Window {
        CryptoModule?: ICryptoLibrary;
    }
}

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
     * Initializes a new instance of this class after attempting to load
     * the underlying cryptographic library in the order the fastest
     * running library to the slowest
     */
    public static async init (externalLibrary: Partial<ICryptoLibrary> = {}): Promise<Crypto> {
        this.external_library = externalLibrary;

        if (!this.runtime_configuration.library) {
            if (await this.load_wasm_library()) {
                return new Crypto();
            }

            if (await this.load_js_library()) {
                return new Crypto();
            }

            throw new Error('Could not initialize an underlying library');
        }

        return new Crypto();
    }

    /**
     * Forces the library to use the Javascript ASM.js underlying
     * cryptographic library if it can
     */
    public static async force_js_library (): Promise<boolean> {
        return this.load_js_library();
    }

    /**
     * Forces the library to use the WASM underlying cryptographic
     * library if it can
     */
    public static async force_wasm_library (): Promise<boolean> {
        return this.load_wasm_library();
    }

    /**
     * Attempts to load a script from a URL
     *
     * @param url
     * @private
     */
    private static async load (url: string): Promise<boolean> {
        if (!await Crypto.url_exists(url)) {
            return false;
        }

        return new Promise((resolve, reject) => {
            const elem = document.createElement('script');
            elem.src = url;
            elem.defer = true;
            elem.async = false;
            elem.crossOrigin = 'anonymous';
            elem.referrerPolicy = 'no-referrer';

            elem.addEventListener('load', () => resolve(true));
            elem.addEventListener('error', () => function (event: ErrorEvent) {
                return reject(new Error(event.message));
            });

            document.head.appendChild(elem);
        });
    }

    /**
     * Attempts to initialize the underlying cryptographic library from an url
     *
     * @param url
     * @param type
     * @private
     */
    private static async load_library (url: string, type: LibraryType): Promise<boolean> {
        if (!await this.load(url)) {
            return false;
        }

        if (!window.CryptoModule) {
            return false;
        }

        const module = await (new (window.CryptoModule as any)()) as ICryptoLibrary;

        if (Object.getOwnPropertyNames(module).length === 0 || typeof module.sha3 === 'undefined') {
            return false;
        }

        CryptoModule.runtime_configuration = {
            type,
            library: module
        };

        return true;
    }

    /**
     * Attempts to load the Javascript ASM.js module as the underlying
     * cryptographic library
     *
     * @private
     */
    private static async load_js_library (): Promise<boolean> {
        if (await this.load_library(
            `https://cdn.jsdelivr.net/npm/@gibme/crypto@${version}/dist/src/loaders/crypto-module.js`,
            LibraryType.JS)) {
            return true;
        }

        // this is a fallback
        return this.load_library('https://testmodule.pages.dev/crypto-module.js', LibraryType.JS);
    }

    /**
     * Attempts to load the WASM module as the underlying cryptographic
     * library
     *
     * @private
     */
    private static async load_wasm_library (): Promise<boolean> {
        if (await this.load_library(
            `https://cdn.jsdelivr.net/npm/@gibme/crypto@${version}/dist/src/loaders/crypto-module-wasm.js`,
            LibraryType.WASM)) {
            return true;
        }

        // this is a fallback
        return this.load_library('https://testmodule.pages.dev/crypto-module-wasm.js', LibraryType.WASM);
    }

    /**
     * Checks if the URL exists
     *
     * @param url
     * @private
     */
    private static async url_exists (url: string): Promise<boolean> {
        const response = await fetch(url, { method: 'HEAD' });

        return response.ok;
    }
}

export { Crypto };
