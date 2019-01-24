# -*- coding:utf-8 -*-

# 生成器函数
def gensquares(N):
    for _ in range(N):
        print(".........")
        yield _ ** 2

for _ in gensquares(2):
    print(_)


# 普通函数
def gensquares(N):
    a = []
    for _ in range(N):
        print(".........")
        a.append(_ ** 2)
    return a

for _ in gensquares(2):
    print(_)


# 生成器表达式
g = (x**2 for x in range(10))
print(g)


# 迭代器对象只能被执行一次
def generator_function():
    for i in range(5):
        yield i
g = generator_function()
for item in g: print(item)
for item in g: print(item)
