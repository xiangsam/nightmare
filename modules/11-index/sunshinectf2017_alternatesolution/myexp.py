'''
Author: Samrito
Date: 2022-02-28 15:49:30
LastEditors: Samrito
LastEditTime: 2022-02-28 16:06:11
'''
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'


def debug(argv=''):
    gdb.attach(io, argv)


io = process(argv=['./alternate_solution'])
#debug('b * main')
#io.sendline(b'37.35928559')
io.sendline(b'NAN')
io.interactive()