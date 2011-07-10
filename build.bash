#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

mkdir -p build
ln -fs ../CIL.dll build/CIL.dll
ln -fs ../LLVMFSharp.dll build/LLVMFSharp.dll
fsc --nologo --target:library --out:build/fig.dll -r CIL.dll -r LLVMFSharp.dll \
    src/Fig/CIL.fs \
    src/Fig/LLVMCodeGen.fs

