# -*- coding:utf-8 -*-

# Case1
if True:
    raise Exception('My error!')
    print("test")


# Case2
try:
    s = None
    if s is None:

        raise NameError       #如果引发NameError异常，后面的代码将不能执行
    print("s 是空对象")        #这句不会执行，但是后面的except还是会走到
except:
    raise
    print("空对象没有长度")


# Case3：
try:
    print(x)
except:
    raise
print("test")
