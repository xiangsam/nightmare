'''
Author: Samrito
Date: 2022-03-05 14:28:27
LastEditors: Samrito
LastEditTime: 2022-03-05 14:35:09
'''
from pwn import *
from z3 import *

target = [b'Dufhbmf', b'pG`imos', b'ewUglpt']
sol = Solver()
inp = []
for i in range(12):
    inp.append(BitVec('%d' % i, 8))

for i in range(0, 12):
    sol.add(target[i % 3][2 * int(i / 3)] - inp[i] == 1)

if sol.check() == sat:
    print('solved')
    solution = sol.model()
    flag = []
    for e in inp:
        flag.append(int(str(solution[e])).to_bytes(1, 'little'))
    print(b''.join(flag))
else:
    print('can not solve')
