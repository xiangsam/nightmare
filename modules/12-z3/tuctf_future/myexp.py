'''
Author: Samrito
Date: 2022-03-04 19:58:04
LastEditors: Samrito
LastEditTime: 2022-03-04 22:23:12
'''
from z3 import *

target = b'\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4'

sol = Solver()
inp = []
mat = [[0 for i in range(5)] for j in range(5)]
for i in range(25):
    inp.append(BitVec('%d' % i, 8))
for i in range(25):
    mat[int(2 * i % 25 / 5)][2 * i % 25 % 5] = inp[7 * i % 25]
auth = [0 for i in range(18)]
auth[0] = mat[0][0] + mat[4][4]
auth[1] = mat[2][1] + mat[0][2]
auth[2] = mat[4][2] + mat[4][1]
auth[3] = mat[1][3] + mat[3][1]
auth[4] = mat[3][4] + mat[1][2]
auth[5] = mat[1][0] + mat[2][3]
auth[6] = mat[2][4] + mat[2][0]
auth[7] = mat[3][2] + mat[3][3] + mat[0][3]
auth[8] = mat[4][0] + mat[0][4] + mat[0][1]
auth[9] = mat[3][3] + mat[2][0]
auth[10] = mat[4][0] + mat[1][2]
auth[11] = mat[0][4] + mat[4][1]
auth[12] = mat[0][3] + mat[0][2]
auth[13] = mat[3][0] + mat[2][0]
auth[14] = mat[1][4] + mat[1][2]
auth[15] = mat[4][3] + mat[2][3]
auth[16] = mat[2][2] + mat[0][2]
auth[17] = mat[1][1] + mat[4][1]

for i in range(len(target)):
    sol.add(auth[i] == target[i])
for i in range(25):
    sol.add(inp[i] > 32)
    sol.add(inp[i] < 127)
if sol.check() == sat:
    print('solved')
    flag = []
    solution = sol.model()
    for i in inp:
        flag.append(int(str(solution[i])).to_bytes(1, 'little'))
    print(b''.join(flag))
else:
    print('can not solve')