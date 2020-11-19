#!/usr/bin/env python3

import numpy as np
import sys
import matplotlib as mpl
import matplotlib.pyplot as plt

x = np.load(sys.argv[1],mmap_mode="r")

if len(sys.argv) == 2:
  plt.plot(x[0:500])
  plt.show()
else:
  plt.plot(x[int(sys.argv[2]):int(sys.argv[2])+500])
  plt.show()
