#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

./build.bash
fsc --nologo --optimize- --target:library --out:SimpleFunctions.dll test/SimpleFunctions.fs
fsc --nologo -r CIL.dll -r LLVMFSharp.dll -r fig.dll test/test.fs
LD_LIBRARY_PATH=~/share/lib/ mono test.exe SimpleFunctions.dll
llvm-dis SimpleFunctions.dll.bc
llvm-as SimpleFunctions.dll.ll

