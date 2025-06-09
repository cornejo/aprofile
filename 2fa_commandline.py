#! /usr/bin/env python3

import json
import sys

print("Please enter the code you received on your trusted device: ", file=sys.stderr)

code = input()

print(json.dumps({"code": code}, indent=2))
