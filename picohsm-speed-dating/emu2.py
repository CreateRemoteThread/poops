#!/usr/bin/env python3

from unicorn import *
from unicorn.arm_const import *

f = open("firmware-mcu.bin","rb")
data = f.read()
f.close()

import struct

from payload import READ_PAYLOAD
# READ_PAYLOAD = b"pew pew\n\x00"

# 71d is exit.
# READ_PAYLOAD = b"b \x00" + b"b " * 10 + b"\x11" * (0x303 - (len(PL_STG3) - 2 + 20)) + PL_STG3 + PL_STG4

import random

read_flag = False

def hexdump(d):
  for chunk in [d[x:x+4] for x in range(0,len(d),4)]:
    print(chunk)

def poops(mu,address,size,user_data):
  if address == 0x08001054 or address == 0x08001055:
    print("[hook] delay - skipping")
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08001094:
    print("[stop] panic. fix something in the stack")
    mu.emu_stop()
  elif address in [0x08000514,0x0800071c]:
    print("[stop] capturing this pointer for socket (again)")
    print(hex(mu.reg_read(UC_ARM_REG_R0)))
    mu.emu_stop()
  elif address == 0x08000cae:
    print("[stop] capturing this pointer for a socket")
    print(hex(mu.reg_read(UC_ARM_REG_R0)))
    mu.emu_stop()
  elif address in (0x08000ad0,0x08000ad1,0x08000ada,0x08000adb):
    print("[hook] w5500_t spi_wait_txe or spi_wait_rxne")
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x080008fa:
    print("[%x:LR:%x] TX:%c" % (mu.reg_read(UC_ARM_REG_PC),mu.reg_read(UC_ARM_REG_LR),mu.reg_read(UC_ARM_REG_R1) & 0xFF))
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08000170 or address == 0x08000171:
    print("[hook] rand_u32")
    mu.reg_write(UC_ARM_REG_R0,random.randint(0,0x1FFFFFFF))
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  else:
    stack_ptr = mu.reg_read(UC_ARM_REG_SP)
    print(" >> PC:%x SP:%x" % (address,stack_ptr))

mu = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
mu.mem_map(0x08000000,2*1024*1024)
mu.mem_map(0x20000000,4*1024*1024)
mu.mem_write(0x08000000,data)
mu.mem_map(0x10000000,2*1024*1024)

mu.mem_map(0xe0000000,4*1024*1024) # stm32 control dma (unknown)
mu.mem_map(0x40000000,4*1024*1024) # stm32 control dma
mu.mem_map(0x50000000,4*1024*1024) # stm32 RNG

payload_addr = 0x10000000
payload_array_addr = 0x10005000

def wpl(data):
  global payload_addr,payload_array_addr
  mu.mem_write(payload_addr,data)
  mu.mem_write(payload_addr + len(data),b"\x00")
  mu.mem_write(payload_array_addr,struct.pack("<l",payload_addr))
  payload_addr += len(data) + 1
  payload_array_addr += 4

mu.hook_add(UC_HOOK_CODE,poops)

mu.reg_write(UC_ARM_REG_PC,0x0800014b)
mu.reg_write(UC_ARM_REG_SP,0x20002000)

try:
  mu.emu_start(0x0800014b,0x08002736+1)
except UcError as e:
  print("ERROR: %s" % e)
  print("PC = %x" % mu.reg_read(UC_ARM_REG_PC))
  print("SP = %x" % mu.reg_read(UC_ARM_REG_SP))
  print("R0 = %x" % mu.reg_read(UC_ARM_REG_R0))
  print("R1 = %x" % mu.reg_read(UC_ARM_REG_R1))
  print("R3 = %x" % mu.reg_read(UC_ARM_REG_R3))
  print("R4 = %x" % mu.reg_read(UC_ARM_REG_R4))
  print("R5 = %x" % mu.reg_read(UC_ARM_REG_R5))
  print(mu.mem_read(0x20000000,0x20))

# print(binascii.hexlify(mu.mem_read(0x10001000,0x10)))
