# -*- coding:utf-8 -*-

# 装饰器demo
def lru_cache(expire=5):
    # 默认5s超时
    def func_wrapper(func):
        def inner(*args, **kwargs):
            # cache 处理 bala bala bala
            return func(*args, **kwargs)
        return inner
    return func_wrapper

@lru_cache(expire=10*60)
def get(request, pk):
    # 省略具体代码
    response = None
    return response

# 带参数的被装饰函数
def debug(func):
    def wrapper(*args, **kwargs):
        print("[DEBUG]: enter {}()".format(func.__name__))
        return func(*args, **kwargs)
    return wrapper

@debug
def say(something):
    print("hello {}!".format(something))
say("带参数的被装饰函数")


# 带参数的装饰器
def logging(level):
    def wrapper(func):
        def inner_wrapper(*args, **kwargs):
            print("[{level}]: enter function {func}()".format(level=level,func=func.__name__))
            return func(*args, **kwargs)
        return inner_wrapper
    return wrapper

@logging(level='INFO')
def say(something):
    print("say {}!".format(something))

say('带参数的装饰器')


# 类装饰器
class logging(object):
    def __init__(self, func):
        self.func = func

    def option(self):
        print("do something...")

    def __call__(self, *args, **kwargs):
        self.option()
        return self.func(*args, **kwargs)
@logging
def say(something):
    print("say {}!".format(something))

say('类装饰器')


# 带参数的类装饰器
class logging(object):
    def __init__(self, level='INFO'):
        self.level = level
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            print("[{0}]: func_name：{1}".format(self.level, func.__name__))
            return func(*args, **kwargs)
        return wrapper

@logging(level='INFO')
def say(something):
    print("say {}".format(something))

say('带参数的类装饰器')


# 多层装饰器的执行顺序
def decorator_a(func):
    print('Get in decorator_a')
    def inner_a(*args, **kwargs):
        print('Get in inner_a')
        return func(*args, **kwargs)
    return inner_a

def decorator_b(func):
    print('Get in decorator_b')
    def inner_b(*args, **kwargs):
        print('Get in inner_b')
        return func(*args, **kwargs)
    return inner_b

@decorator_b
@decorator_a
def f(x):
    print('Get in f')
    return x * 2

f(1)
