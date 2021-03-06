#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

./build.bash

#fsc --nologo --debug --optimize- --target:library --out:build/InternalCalls.dll test/InternalCalls.fs
#monodis build/InternalCalls.dll > build/InternalCalls.il
#mono build/CompileCIL.exe build/InternalCalls.dll build/InternalCalls.bc
#llvm-dis build/InternalCalls.bc
#llc -march=x86-64 -filetype=obj build/InternalCalls.bc

# Simple main
fsc --nologo --debug --optimize- --target:exe --out:build/SimpleMain.exe test/SimpleMain.fs
monodis build/SimpleMain.exe > build/SimpleMain.il
mono build/CompileCIL.exe build/SimpleMain.exe build/SimpleMain.bc
llvm-dis build/SimpleMain.bc
opt -O2 build/SimpleMain.bc > build/SimpleMain-opt.bc
llvm-dis build/SimpleMain-opt.bc
llc -march=x86-64 -filetype=obj build/SimpleMain.bc
gcc -o build/simplemain build/SimpleMain.o
./build/simplemain

# Simple functions that we link against a C program
fsc --nologo --debug --optimize- --target:library --out:build/SimpleFunctions.dll test/SimpleFunctions.fs
monodis build/SimpleFunctions.dll > build/SimpleFunctions.il
mono build/CompileCIL.exe build/SimpleFunctions.dll build/SimpleFunctions.bc
llvm-dis build/SimpleFunctions.bc
opt -O2 build/SimpleFunctions.bc > build/SimpleFunctions-opt.bc
llvm-dis build/SimpleFunctions-opt.bc
llc -march=x86-64 -filetype=obj build/SimpleFunctions.bc

# link our F# code against TestSimpleFuns.c and run it
gcc -o build/simplefuns build/SimpleFunctions.o test/TestSimpleFuns.c
./build/simplefuns

## Struct Test
#dmcs -target:library -out:build/StructTest.dll test/StructTest.cs
#monodis build/StructTest.dll > build/StructTest.il
#mono build/CompileCIL.exe build/StructTest.dll build/StructTest.bc
#
