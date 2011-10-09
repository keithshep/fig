#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

./build.bash
#fsc --nologo --debug --out:build/ParseCIL.exe -r Mono.Cecil.dll -r Mono.Cecil.Rocks.dll -r build/fig.dll test/ParseCIL.fs
fsc --nologo --debug --out:build/CompileCIL.exe -r Mono.Cecil.dll -r Mono.Cecil.Rocks.dll -r LLVMFSharp.dll -r build/fig.dll test/CompileCIL.fs

# test out the our new CIL parsing module against some simple F# functions
fsc --nologo --debug --optimize- --target:exe --out:build/SimpleMain.exe test/SimpleMain.fs
monodis build/SimpleMain.exe > build/SimpleMain.il
fsc --nologo --debug --optimize+ --target:library --out:build/SimpleFunctions.dll test/SimpleFunctions.fs
monodis build/SimpleFunctions.dll > build/SimpleFunctions.il
#mono build/ParseCIL.exe build/SimpleFunctions.dll
dmcs -target:exe -out:build/cstest.exe test/cstest.cs
monodis build/cstest.exe > build/cstest.il

# now use our LLVM compiler to create a .o file from our simple F# functions
mono build/CompileCIL.exe build/SimpleFunctions.dll build/SimpleFunctions.bc
llvm-dis build/SimpleFunctions.bc
opt -O2 build/SimpleFunctions.bc > build/SimpleFunctions-opt.bc
llvm-dis build/SimpleFunctions-opt.bc
llc -march=x86-64 -filetype=obj build/SimpleFunctions.bc

# link our F# code against TestSimpleFuns.c and run it
gcc -o build/simplefuns build/SimpleFunctions.o test/TestSimpleFuns.c
./build/simplefuns

mono build/CompileCIL.exe build/SimpleMain.exe build/SimpleMain.bc
llvm-dis build/SimpleMain.bc
llc -march=x86-64 -filetype=obj build/SimpleMain.bc
gcc -o build/simplemain build/SimpleMain.o
./build/simplemain

# translate our LLVM bitcode to C
#llc -march=c build/SimpleFunctions.bc

