#!/usr/bin/env python3

import sys
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt

x = np.load(sys.argv[1],mmap_mode="r")

BitCounter = 0
i = 0
lastI = 0
outBin = ""
while i + 60 < len(x):
  if np.mean(x[i:i+10]) > 150:
    outBin += "1"
  else:
    outBin +="0"
  print("%d,%d" % (i,i - lastI))
  lastI = i
  BitCounter += 1
  i += 60
  try:
    while not (x[i-1] < 100 and x[i] > 100):
      i += 1
  except:
    break

print(BitCounter)
print(outBin)
print(int(outBin.replace("01","1"),2))
