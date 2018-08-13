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


try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

# this should be a dict
auth_table = [("user", "password", 10),
              ("tech", "tech", 1),
              ("root", "Zte521", 2),
              ("root", "xc3511", 2),
              ("root", "vizxv", 1),
              ("admin", "admin", 1),
              ("root", "admin", 1),
              ("root", "888888", 1),
              ("root", "xmhdipc", 1),
              ("root", "juantech", 1),
              ("root", "123456", 1),
              ("root", "54321", 1),
              ("support", "support", 1),
              ("root", "", 1),
              ("admin", "password", 1),
              ("root", "root", 1),
              ("root", "root", 1),
              ("user", "user", 1),
              ("admin", "admin1234", 1),
              ("admin", "smcadmin", 1),
              ("root", "klv123", 1),
              ("root", "klv1234", 1),
              ("root", "hi3518", 1),
              ("root", "jvbzd", 1),
              ("root", "anko", 1),
              ("root", "zlxx.", 1),
              ("root", "system", 1)]

auth_queue = iModule.PriorityQueue()
ip_prompt_queue = deque(maxlen=100)
queue = Queue.Queue()

def cook(pkt):
    try:
        global lastRecv
        lastRecv = time.time()
        if pkt[TCP].flags == 17 and pkt[IP].src not in ip_prompt_queue:
            queue.put(pkt[IP].src)
            print "23 port opened: %s " % (pkt[IP].src)
            ip_prompt_queue.append(pkt[ip].src)
    except:
        pass

def start():
    '''Init threads'''
    scanner_list = []
    start_time = datetime.now()
    state = iModule.SendState()
    send_syn_thread = iModule.send_syn(sys.argv[1], state)

    try:
        send_syn_thread.start()
    except:
        print "[Error] Start send_syn failed!"
        sys.exit()

    sniffer_thread = iModule.Sniffer(cook)
    try:
        sniffer_thread.daemon = True
        sniffer_thread.start()
    except:
        print "[Error] Start sniffer failed!"
        sys.exit()

    for i in range(int(sys.argv[2])):
        t = iModule.Scanner(queue, state, auth_queue)
        try:
            t.start()
        except:
            pass
        scanner_list.append(t)

    while True:
        time.sleep(1)
        if time.time() - state.lastRecv > 30 and state.exitFlag == 1:
            state.exitFlag = 2
        elif state.exitFlag == 3:
            end_time = datetime.now()
            print "iScanner completes..."
            print "It totally costs: %d seconds..." % (end_time - start_time).seconds
            break

        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "usage: iScanner.py ip_filename thread_number"
        print "example :iScanner.py ip_filename 20"
        sys.exit(1)

    for item in auth_table:
        auth_queue.push(item[0:2], item[-1])

    start()
