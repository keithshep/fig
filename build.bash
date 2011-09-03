#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

mkdir -p build
ln -fs ../CIL.dll build/CIL.dll
ln -fs ../LLVMFSharp.dll build/LLVMFSharp.dll
ln -fs ../Mono.Cecil.dll build/Mono.Cecil.dll
ln -fs ../Mono.Cecil.Rocks.dll build/Mono.Cecil.Rocks.dll
fsc --nologo --target:library --out:build/fig.dll \
    -r CIL.dll -r LLVMFSharp.dll -r Mono.Cecil.dll -r Mono.Cecil.Rocks.dll \
    src/Fig/CecilExt.fs \
    src/Fig/LLVMCodeGen.fs

