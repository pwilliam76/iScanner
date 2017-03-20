#!/usr/bin/env python
#encoding:utf-8

import heapq
import threading
from scapy.all import *

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._index = 0

    def push(self, pair, priority):
        heapq.heappush(self._queue, (-priority, self._index, pair))
        self._index += 1

    def pop(self):
        return heapq.heappop(self._queue)[-1]

class send_syn(threading.Thread):
    '''send dport=23 package'''
    def __init__(self, filename):
        threading.Thread.__init__(self)
        self._ip_list = []
        self.read_ip(self, filename)

    def run(self):
        global exitFlag
        print "Start to ip splitting"
        pkt = IP()/TCP(sport = 2222, dport=[23], flags="S")
        for ip in self._ip:
            pkt[IP].dst = num2ip(ip)
            try:
                send(pkt, verbose = 0)
            except:
                pass
        exitFlag = 1
    
    def read_ip(self, filename):
        ip_f = open(filename, 'r')
        for line in ip_f.readlines():
            _ip_list.append(line.strip())

class sniffer(threading.Thread):
    '''receive sport=2222 package'''
    def __init(self,callback):
        threading.Thread.__init__(self)
        self._cb = callback

    def run(self, callback):
        print "Start to sniffing..."
        sniff(filter = "tcp and dst port 2222 and src port 23", prn = self._cb)

class Scanner(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        print "starting scanner threading..."
        while True:
            ip_port = None
            queueLocker.acquire()
            if self.queue.empty() and exitFlag == 2 or exitFlag == 3:
                queueLocker.release()
                exitFlag = 3
                break
            elif self.queue.empty():
                queueLocker.release()
                time.sleep(3)
                continue
            try:
                ip_port = self.queue.get(block=False)
            except:
                pass
            queueLocker.release()
            if ip_port:
                pass
            else:
                time.sleep(3)
                continue
            
            #password guessing
            con = Connection(copy.deepcopy(ip_port), copy.deepcopy(auth_queue))
            while con._state:
                con.run()
            
            con.exit()
            del con
            