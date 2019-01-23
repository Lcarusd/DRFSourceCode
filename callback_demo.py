# -*- coding:utf-8 -*-

# 回调函数1:生成一个2k形式的偶数
def double(x):
    return x * 2


# 回调函数2:生成一个4k形式的偶数
def quadruple(x):
    return x * 4


# 中间函数:接受一个生成偶数的函数作为参数并返回奇数
def getOddNumber(k, getEvenNumber):
    return 1 + getEvenNumber(k)


# 起始函数
def main():
    k = 1
    i = getOddNumber(k, double)     # 生成2k+1形式的奇数
    print(i)
    i = getOddNumber(k, quadruple)   # 生成4k+1形式的奇数
    print(i)
    i = getOddNumber(k, lambda x: x * 8)    # 生成8k+1形式的奇数
    print(i)


if __name__ == "__main__":
    main()
