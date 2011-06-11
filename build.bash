#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

fsc --nologo --target:library --out:fig.dll -r CIL.dll -r LLVMFSharp.dll \
    src/Fig/LLVMCodeGen.fs

