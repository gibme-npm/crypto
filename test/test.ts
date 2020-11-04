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

import { execSync } from 'child_process';
import { env_is_set } from './core';

const version = process.versions.node;
const majorVersion = parseInt(version.split('.')[0], 10);

/**
 * Something goofy going on with Mocha running the WASM tests
 * under Node v20+. It will exit immediately, throw no errors,
 * and skip all the tests, and then report 0 passing and 0 failed.
 * However, forcing the WASM crypto module via regular CLI or
 * browser use works just fine on Node v20.
 *
 * What we're doing here is grabbing the node version and if we
 * are trying to test the WASM crypto module, and if so, redirecting
 * the test over to a version that uses the `node:test` package
 * that works just fine.
 */
try {
    if (majorVersion >= 20 && env_is_set(process.env.FORCE_WASM)) {
        execSync('npm run test:mocha-20', { stdio: 'inherit' });
    } else {
        execSync('npm run test:mocha-18', { stdio: 'inherit' });
    }
} catch {
    process.exit(1);
}
