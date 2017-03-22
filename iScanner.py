#!/usr/bin/env python
# encoding:utf-8

import pexpect
import heapq
from datetime import datetime
import time
import Queue
import sys
from collections import deque

import iModule
import iState
from dictionary import dict_table


auth_queue = iModule.PriorityQueue()
ip_prompt_queue = deque(maxlen=100)
queue = Queue.Queue()

def read_ip(filename):
    try:
        ip_f = open(filename, 'r')
    except IOError:
        print "cann't open file %s" % filename
    else:
        for line in ip_f.readlines():
            queue.put(line.strip())
        print "read %s lines finished." % filename

def start():
    '''Init threads'''
    
    for item in dict_table:
        auth_queue.push(item[0:2],item[-1])
    
    read_ip(sys.argv[1])
    
    start_time = datetime.now()
    state = iModule.SendState()
    
    for i in range(int(sys.argv[2])):
        state.exitFlag.append(0)
        t = iModule.Scanner(queue, state, auth_queue, i)
        try:
            t.start()
        except:
            pass

    while True:
        time.sleep(2)
        state.exitLock.acquire()
        count = 0
        for index in range(len(state.exitFlag)):
            if state.exitFlag[index] == 1:
                count += 1
        state.exitLock.release()
        if count == len(state.exitFlag):
            end_time = datetime.now()
            print "iScanner completes..."
            print "It totally costs: %d seconds..." % (end_time - start_time).seconds
            break
        else:
            continue
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "usage: iScanner.py ip_filename thread_number"
        print "example :iScanner.py ip_filename 20"
        sys.exit(1)
    start()
