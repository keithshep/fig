#!/bin/bash

# exit on error and don't allow the use of unset variables
set -o errexit
set -o nounset

for i in /Library/Frameworks/Mono.framework/Versions/2.10.5/lib/mono/4.0/*.dll
do
    echo "=========== PARSING $i ============"
    mono build/ParseCIL.exe $i
done

