#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset
set -x

rm -f LLVMCodeGen.exe helloworld.exe* fig.dll SimpleFunctions.dll test.exe

