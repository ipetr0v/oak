#!/bin/bash
set -o errexit

external/emscripten/emcc "$@"
