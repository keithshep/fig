#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

mkdir -p build
ln -fs ../LLVMFSharp.dll build/LLVMFSharp.dll
ln -fs ../Mono.Cecil.dll build/Mono.Cecil.dll
ln -fs ../Mono.Cecil.Rocks.dll build/Mono.Cecil.Rocks.dll
fsc --nologo --optimize- --debug --warnon:1182 --out:build/CompileCIL.exe \
    -r LLVMFSharp.dll -r Mono.Cecil.dll -r Mono.Cecil.Rocks.dll \
    src/Fig/CecilExt.fs \
    src/Fig/LLVMCodeGen.fs \
    src/Fig/CompileCIL.fs

clang -c src-c/fig_runtime.c -emit-llvm -o build/fig_runtime.bc
#clang src-c/fig_runtime.c -S -emit-llvm -o -
#clang -c src-c/fig_runtime.c -emit-llvm -o - | llvm-dis
