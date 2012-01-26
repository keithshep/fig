#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

mkdir -p build
fsc --nologo --debug --warnon:1182 --out:build/ParseCIL.exe \
    src/Fig/IOUtil.fs \
    src/Fig/ParseCode.fs \
    src/Fig/AssemblyParser.fs \
    src/Fig/Disassemble.fs \
    src/Fig/AssemblyResolution.fs \
    src/Fig/ParseCIL.fs

