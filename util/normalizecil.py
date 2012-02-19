import re
import sys

for line in sys.stdin:
    line = re.sub(r'(.*)//[^\n]*(.*)', r'\1\2', line)
    line = re.sub(r'(^|.*\s)(ldloc|stloc|ldarg|ldc.i4)\.(\d\s*)', r'\1\2 \3', line)
    line = re.sub(r'(.*\S)\.s(\s.*)', r'\1\2', line)
    print line,

