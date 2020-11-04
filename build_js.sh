#!/bin/bash

# Set up emscripten
if [[ -z "${EMSDK}" ]]; then
  echo "Installing emscripten..."
  echo ""
  if [[ ! -e ./emsdk/emsdk ]]; then
    git submodule init
    git submodule update
  fi
  cd emsdk && git pull
  ./emsdk install latest && ./emsdk activate latest
  source ./emsdk_env.sh
  cd ..
fi

# This applies a patch to fastcomp to make sure that the
# environment is set correctly for react environments
# patch -N --verbose emsdk/fastcomp/emscripten/src/shell.js scripts/emscripten.patch

mkdir -p build.js && cd build.js
if ! test -f crypto-module.js; then
  rm -rf *
fi

mkdir -p ../dist
emcmake cmake .. -DARCH=default -DBUILD_WASM=1 -DBUILD_JS=0 -DBUILD_NODE=0 -DENGLISH_ONLY=1
make && cp crypto-module-wasm.js ../dist
emcmake cmake .. -DARCH=default -DBUILD_WASM=0 -DBUILD_JS=1 -DBUILD_NODE=0 -DENGLISH_ONLY=1
make && cp crypto-module.js ../dist
