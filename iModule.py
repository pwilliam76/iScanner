#!/usr/bin/env python
# encoding:utf-8

import heapq
import threading
from scapy.all import *
import pexpect
import Queue
import iState
import copy

import utils


class SendState:
    def __init__(self):
        self.exitFlag = 0
        self.lastRecv = 0


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

    def __init__(self, filename, st):
        threading.Thread.__init__(self)
        self._ip_list = []
        self.read_ip(filename)
        self.st = st
        print 'send_sy initialized'

    def run(self):
        print "Start to ip splitting"
        pkt = IP()/TCP(sport=22222, dport=[23], flags="S")
        for ip in self._ip_list:
            pkt[IP].dst = utils.num2ip(ip)
            try:
                send(pkt, verbose=0)
            except:
                pass
        self.st.exitFlag = 1

    def read_ip(self, filename):
        try:
            ip_f = open(filename, 'r')
        except IOError:
            print "cann't open file %s" % filename
        else:
            for line in ip_f.readlines():
                self._ip_list.append(line.strip())
            print "read %s lines finished." % filename


class sniffer(threading.Thread):
    '''receive sport=2222 package'''

    def __init__(self, callback):
        threading.Thread.__init__(self)
        self._cb = callback

    def run(self):
        print "Start to sniffing..."
        sniff(filter="tcp and dst port 2222 and src port 23", prn=self._cb)


class Scanner(threading.Thread):
    def __init__(self, q, st, aq):
        threading.Thread.__init__(self)
        self.queue = q
        self.queue_locker = threading.Lock()
        self.st = st
        self.authqueue = aq

    def run(self):
        print "starting scanner threading..."
        while True:
            ip_port = None
            self.queue_locker.acquire()
            if self.queue.empty() and self.st.exitFlag == 2 or self.st.exitFlag == 3:
                self.queueLocker.release()
                st.exitFlag = 3
                break
            elif self.queue.empty():
                self.queue_locker.release()
                time.sleep(3)
                continue
            try:
                ip_port = self.queue.get(block=False)
            except:
                pass
            self.queue_locker.release()
            if ip_port:
                pass
            else:
                time.sleep(3)
                continue

            # password guessing
            con = iState.Connection(copy.deepcopy(
                ip_port), copy.deepcopy(auth_queue))
            while con._state:
                con.run()

            con.exit()
            del con
