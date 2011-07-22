#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

./build.bash
dmcs -target:library -out:build/cstest.dll test/cstest.cs
fsc --nologo --target:library --out:build/SimpleFunctions.dll test/SimpleFunctions.fs
fsc --nologo --out:build/test.exe -r CIL.dll -r LLVMFSharp.dll -r build/fig.dll test/test.fs
#mono build/test.exe build/SimpleFunctions.dll build/SimpleFunctions.bc
mono build/test.exe build/SimpleFunctions.dll

#llc -march=c build/SimpleFunctions.bc
#llc -filetype=obj build/SimpleFunctions.bc
#llvm-dis build/SimpleFunctions.bc
#gcc -o build/simplefuns build/SimpleFunctions.o test/TestSimpleFuns.c

