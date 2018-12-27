# -*- coding:utf-8  -*-

"""
判断文件夹是否存在，不存在就创建
"""

# import os
#
#
# file_path = '{0}/data'.format(os.getcwd())
# if not os.path.isdir(file_path):
#     os.makedirs(file_path)

a = 6
b = 8

for i in range(1, b):
    for j in range(1, a):
        if j == 2:
            continue
        print (j)