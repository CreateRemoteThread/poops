#!/usr/bin/env python3
import sys
from pwnlib.asm import asm,disasm
import pwnlib.shellcraft.thumb as sc

data = sc.mov("r0",0xdeadbeef)

print(data)
print(len(x))

