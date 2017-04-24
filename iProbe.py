#!/usr/bin/env python
# encoding:utf-8

import pexpect
import heapq
from datetime import datetime
import time
import Queue
import sys
from collections import deque
import argparse

import iModule

from iDict import dict_table


auth_queue = iModule.PriorityQueue()
ip_prompt_queue = deque(maxlen=100)
ip_queue = Queue.Queue()

def read_ip(filename):
    try:
        ip_f = open(filename, 'r')
    except IOError:
        print "cann't open file %s" % filename
    else:
        for line in ip_f.readlines():
            ip_queue.put(line.strip())
        print "read %s lines finished." % filename

def start(args):
    '''Init threads'''
    
    for item in dict_table:
        auth_queue.push(item[0:2],item[-1])
    
    read_ip(args.file)
    
    start_time = datetime.now()
    state = iModule.SendState()
    
    for i in range(args.thread):
        state.exitFlag.append(0)
        t = iModule.Probe(ip_queue, state, auth_queue, i, args.proto)
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
            print "iProbe completes..."
            print "It totally costs: %d seconds..." % (end_time - start_time).seconds
            break
        else:
            continue
    sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser();
    parser.add_argument("file", help="IP address list file.")
    parser.add_argument("proto", help="The protocal to probe weak password.", choices=["telnet", "ssh"])
    parser.add_argument("dict", help="Word dictionary to probe weak password.")
    parser.add_argument("-t", "--thread", help="The thread used to scanning.", type=int, default=20)
    args = parser.parse_args()

    start(args)