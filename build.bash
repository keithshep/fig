#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

mkdir -p build
ln -fs ../LLVMFSharp.dll build/LLVMFSharp.dll
#fsc --nologo --optimize- --debug --warnon:1182 --out:build/CompileCIL.exe
fsc --nologo --debug --out:build/CompileCIL.exe \
    -r LLVMFSharp.dll \
    src/Fig/IOUtil.fs \
    src/Fig/ParseCode.fs \
    src/Fig/AssemblyParser.fs \
    src/Fig/AssemblyResolution.fs \
    src/Fig/LLVMCodeGen.fs \
    src/Fig/CompileCIL.fs

clang -c src-c/fig_runtime.c -emit-llvm -o build/fig_runtime.bc
#clang src-c/fig_runtime.c -S -emit-llvm -o -
#clang -c src-c/fig_runtime.c -emit-llvm -o - | llvm-dis
