#!/bin/bash
set -o errexit

export LLVM_ROOT='external/emscripten_fastcomp'
export EMSCRIPTEN_NATIVE_OPTIMIZER='external/emscripten_fastcomp/optimizer'
export BINARYEN_ROOT='external/emscripten_fastcomp/'
export NODE_JS=''
export EMSCRIPTEN_ROOT='external/emscripten'
export SPIDERMONKEY_ENGINE=''
export EM_EXCLUSIVE_CACHE_ACCESS=1
export EMCC_SKIP_SANITY_CHECK=1
export EMCC_WASM_BACKEND=1

echo BINARYEN_ROOT is $BINARYEN_ROOT

#mkdir -p "tmp/emscripten_cache"

#export EM_CACHE="tmp/emscripten_cache"
#export TEMP_DIR="tmp"

# Prepare the cache content so emscripten doesn't keep rebuilding it
#cp -r toolchain/emscripten_cache/* tmp/emscripten_cache

external/emscripten/emcc "$@"

# Remove the first line of .d file
#find . -name "*.d" -exec sed -i '2d' {} \;
