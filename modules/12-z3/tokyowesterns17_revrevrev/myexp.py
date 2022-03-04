'''
Author: Samrito
Date: 2022-03-03 16:16:28
LastEditors: Samrito
LastEditTime: 2022-03-04 19:34:23
'''
from z3 import *

target = b'\x41\x29\xd9\x65\xa1\xf1\xe1\xc9\x19\x09\x93\x13\xa1\x09\xb9\x49\xb9\x89\xdd\x61\x31\x69\xa1\xf1\x71\x21\x9d\xd5\x3d\x15\xd5'

temp1 = []
for e in target:
    temp1.append(e ^ 0xff)
sol = Solver()
unknown_sol = []
for i in range(0, len(temp1)):
    unknown_sol.append(BitVec('%d' % i, 9))
for i in range(0, len(temp1)):
    x = (2 * (unknown_sol[i] & 0x55)) | ((unknown_sol[i] >> 1) & 0x55)
    y = (4 * (x & 0x33)) | ((x >> 2) & 0x33)
    z = ((16 * y) | (y >> 4)) & 0xff
    sol.add(z == temp1[i])
temp2 = []

if sol.check() == sat:
    print('solved')
    solution = sol.model()
    for i in range(0, len(temp1)):
        temp2.append(int(str(solution[unknown_sol[i]])).to_bytes(1, 'little'))
else:
    print('can not solve')
print(b''.join(temp2))
flag = temp2[::-1]
print(b''.join(flag).decode('utf-8'))

