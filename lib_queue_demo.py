#!/usr/bin/env python
# -*- coding:utf-8 -*-

import time
import queue
import threading


def worker(i):
    while True:
        item = q.get()
        if item is None:
            print("线程%s发现了一个None！" % i)
            break
        time.sleep(0.5)
        print("线程%s将任务<%s>完成了！" % (i, item))
        q.task_done()   # 做完后发出任务完成信号，然后继续下一个任务


if __name__ == '__main__':
    # 指定线程数
    num_of_threads = 40

    # 创建一个FIFO队列对象，不指定maxsize
    q = queue.Queue()

    # 创建指定个数的工作线程，并将他们放到线程池threads中
    threads = []
    for i in range(1, num_of_threads + 1):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    # 模拟20个任务
    source = [i for i in range(1, 100000000)]

    # 将任务源里的任务逐个放入队列，每隔0.5秒发布一个新任务
    for item in source:
        time.sleep(0.5)
        q.put(item)

    # 阻塞队列直到队列里的任务都完成了
    q.join()

    # 停止工作线程
    for i in range(num_of_threads):
        q.put(None)
    for t in threads:
        t.join()
    print("工作已完成！")
