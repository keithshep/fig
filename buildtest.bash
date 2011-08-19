#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

./build.bash
dmcs -target:library -out:build/cstest.dll test/cstest.cs
fsc --nologo --out:build/test.exe -r CIL.dll -r LLVMFSharp.dll -r build/fig.dll test/test.fs
fsc --nologo --out:build/CompileCIL.exe -r CIL.dll -r LLVMFSharp.dll -r build/fig.dll test/CompileCIL.fs

# test out the our new CIL parsing module against some simple F# functions
fsc --nologo --target:library --out:build/SimpleFunctions.dll test/SimpleFunctions.fs
mono build/test.exe build/SimpleFunctions.dll

# now use our LLVM compiler to create a .o file from our simple F# functions
mono build/CompileCIL.exe build/SimpleFunctions.dll build/SimpleFunctions.bc
llc -march=x86-64 -filetype=obj build/SimpleFunctions.bc

# link our F# code against TestSimpleFuns.c and run it
gcc -o build/simplefuns build/SimpleFunctions.o test/TestSimpleFuns.c
./build/simplefuns

# translate our LLVM bitcode to C and dissasemble it (just for fun)
llc -march=c build/SimpleFunctions.bc
llvm-dis build/SimpleFunctions.bc

