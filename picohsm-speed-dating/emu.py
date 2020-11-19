#!/usr/bin/env python3

import binascii
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
  if address == 0x08000440:
    print("Returning at address 0x08000440")
  elif address in [0x08000cc0,0x08000cc1]:
    mu.emu_stop()
  elif address in [0x080006ee,0x080006ef]:
    print("[stop] capturing this ptr")
    print(hex(mu.reg_read(UC_ARM_REG_R0)))
    mu.emu_stop()
  elif address in [0x080004f6,0x080004f7]: # ??????
    print("[hook] entering handle_client naturally")
    print(hex(mu.reg_read(UC_ARM_REG_SP)))
    mu.emu_stop()
  elif address == 0x0800072a or address == 0x0800072b:
    print("[hook] pre-disconnect hook.")
    print(hex(mu.reg_read(UC_ARM_REG_R0)))
    # mu.emu_stop()
  elif address == 0x08000912 or address == 0x08000913:
    print("[hook] str r5,[r3,#4] at 0x08000912")
    print("R3: %s" % hex(mu.reg_read(UC_ARM_REG_R3)))
    print("R4: %s" % hex(mu.reg_read(UC_ARM_REG_R4)))
    print("R5: %s" % hex(mu.reg_read(UC_ARM_REG_R5)))
    print("SP: %s" % hex(mu.reg_read(UC_ARM_REG_SP)))
  elif address in (0x08000ad0,0x08000ad1,0x08000ada,0x08000adb):
    print("[hook] w5500_t spi_wait_txe or spi_wait_rxne")
    mu.reg_write(UC_ARM_REG_PC,0x08000501)
  elif address == 0x080004f6 or address == 0x080004f7:
    print("Bypassing socket::avail")
    mu.reg_write(UC_ARM_REG_R0,1)
    mu.reg_write(UC_ARM_REG_PC,0x08000501)
  elif address == 0x080001fc or address == 0x080001fd:
    print("[external call] verify_pin: returning false")
    mu.reg_write(UC_ARM_REG_R0,0)
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08001054 or address == 0x08001055:
    print("[hook] delay - skipping")
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08000170 or address == 0x08000171:
    print("[hook] rand_u32")
    mu.reg_write(UC_ARM_REG_R0,random.randint(0,0x1FFFFFFF))
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08001038 or address == 0x08001039:
    print("[hook] socket::print")
    print(hex(mu.reg_read(UC_ARM_REG_R0)))
    print(hex(mu.reg_read(UC_ARM_REG_R4)))
    print(mu.mem_read(mu.reg_read(UC_ARM_REG_R1),0x10))
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08001018 or address == 0x0801019:
    global READ_PAYLOAD,read_flag
    r_addr = mu.reg_read(UC_ARM_REG_R1)
    print("[hook] read to %x" % r_addr)
    if len(READ_PAYLOAD) > 0x400:
      mu.mem_write(r_addr,READ_PAYLOAD[0:0x400])
    else:
      mu.mem_write(r_addr,READ_PAYLOAD)
    mu.reg_write(UC_ARM_REG_R0,len(READ_PAYLOAD) - 1)
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
    if read_flag is True:
      mu.emu_stop()
    else:
      read_flag = True
  elif address == 0x08000936 or address == 0x08000937:
    print("rx (key lock check), bypassing")
    mu.reg_write(UC_ARM_REG_R0,2)
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x080008fa:
    print("[%x:LR:%x] TX:%c" % (mu.reg_read(UC_ARM_REG_PC),mu.reg_read(UC_ARM_REG_LR),mu.reg_read(UC_ARM_REG_R1) & 0xFF))
    mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR))
  elif address == 0x08000532 or address == 0x08000533:
    print("[hook] exiting from handle_client - stack fixup")
    data = mu.mem_read(0x20000000,2*1024*1024)
    f_log = open("crash.stack","wb")
    f_log.write(data)
    f_log.close()
  else:
    stack_ptr = mu.reg_read(UC_ARM_REG_SP)
    data_ = mu.mem_read(address,4)
    print(" >> PC:%x SP:%x [%s]" % (address,stack_ptr,binascii.hexlify(data_)))

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
  hexdump(mu.mem_read(mu.reg_read(UC_ARM_REG_PC),0x20))

