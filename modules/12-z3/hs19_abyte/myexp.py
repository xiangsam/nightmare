'''
Author: Samrito
Date: 2022-03-03 15:51:02
LastEditors: Samrito
LastEditTime: 2022-03-03 16:01:33
'''

s1 = b'irbugzv1v^x1t^jo1v^e5^v@2^9i3c@138|'

flag = []
for e in s1:
    flag.append(chr(e ^ 1))
print(''.join(flag))