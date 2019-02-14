# -*- coding:utf-8 -*-

"""一行Python代码能做什么"""

print('\n'.join([''.join(
    [('Lcarusd'[(x-y)%7] if ((x*0.05)**2+(y*0.1)**2-1)**3-(x*0.05)**2*(y*0.1)**3<=0 else' ')
                          for x in range(-30,30)]) for y in range(15,-15,-1)]))


# print('\n'.join([''.join(['*'if abs((lambda a:lambda z,c,n:a(a,z,c,n))(lambda s,z,c,n:z if n==0else s(s,z*z+c,c,n-1))(0,0.02*x+0.05j*y,40)) else' 'for x in range(-80,20)])for y in range(-20,20)]))
# print('\n'.join([''.join(['*'if abs((lambda a:lambda z,c,n:a(a,z,c,n))(lambda s,z,c,n:z if n==0else s(s,z*z+c,c,n-1))(0,0.02*x+0.05j*y,40*2)) else' 'for x in range(-80,20)])for y in range(-20,20)]))

# 打印九九乘法表
print('\n'.join([' '.join(['%s*%s=%-2s' % (y,x,x*y) for y in range(1,x+1)]) for x in range(1,10)]))

# 计算1-1000之间的素数
print(*(i for i in range(2, 1000) if all(tuple(i%j for j in range(2, int(i**.5))))))


# 一行代码实现变量值的交换
a, b = 1, 2; a, b = b, a

#
print(' '.join(["fizz"[x % 3 * 4:]+"buzz"[x % 5 * 4:] or str(x) for x in range(1, 101)]))


print('\n'.join([''.join(['*'if abs((lambda a: lambda z, c, n: a(a, z, c, n))(lambda s, z, c, n: z if n == 0 else s(s, z*z+c, c, n-1))(0, 0.02*x+0.05j*y, 40)) < 2 else ' ' for x in range(-80, 20)]) for y in range(-20, 20)]))

[__import__('sys').stdout.write('\n'.join('.' * i + 'Q' + '.' * (8-i-1) for i in vec) + "\n========\n") for vec in __import__('itertools').permutations(range(8)) if 8 == len(set(vec[i]+i for i in range(8))) == len(set(vec[i]-i for i in range(8)))]


# while 1:import random;print(random.choice('╱╲'), end='')

# import antigravity


import this

# import ann_visualizer
# ann_viz(model, view=True, filename="network.gv", title="MyNeural Network")

