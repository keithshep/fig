#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

rm -f \
    LLVMCodeGen.exe \
    fig.dll \
    SimpleFunctions.dll \
    SimpleFunctions.dll.bc \
    SimpleFunctions.dll.ll \
    test.exe

