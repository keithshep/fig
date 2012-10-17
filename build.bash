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

