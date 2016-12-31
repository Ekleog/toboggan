#!/usr/bin/env python3

import sys
print("echo:", sys.argv[1], file=sys.stderr)

print('{ "decision": "allow" }')
