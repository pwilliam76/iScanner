#!/usr/bin/env python
# encoding:utf-8

import heapq
import threading
from scapy.all import *
import pexpect
import Queue
import sys
import iState
import copy

import utils


class SendState:
    def __init__(self):
        self.exitLock = threading.Lock()
        self.exitFlag = []

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._index = 0

    def push(self, pair, priority):
        heapq.heappush(self._queue, (-priority, self._index, pair))
        self._index += 1

    def pop(self):
        return heapq.heappop(self._queue)[-1]

    def empty(self):
        if len(self._queue):
            return False
        else:
            return True


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
            pkt[IP].dst = ip
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
    '''receive sport=22222 package'''

    def __init__(self, callback):
        threading.Thread.__init__(self)
        self._cb = callback

    def run(self):
        print "Start to sniffing..."
        sniff(filter="tcp and dst port 22222 and src port 23", prn=self._cb)



class Scanner(threading.Thread):
    def __init__(self, q, st, aq, i):
        threading.Thread.__init__(self)
        self.queue = q
        self.queue_locker = threading.Lock()
        self.st = st
        self.auth_queue = aq
        self.index = i
        self.log_file = None

    def run(self):
        print "starting scanner threading..."
        try:
            self.log_file = open("log/telnet-%d" % self.index, "w")
        except:
            self.log_file = sys.stdout

        while True:
            ip = None
            self.queue_locker.acquire()
            if self.queue.empty():
                self.queue_locker.release()
                self.st.exitLock.acquire()
                self.st.exitFlag[self.index] = 1
                self.st.exitLock.release()
                
                if self.log_file != sys.stdout:
                    self.log_file.close()
                break
            try:
                ip = self.queue.get(block=False)
            except:
                pass
            self.queue_locker.release()
            
            self.log_file.write("\r\n#!*********** %s **********!#\r\n" % ip)
            # password guessing
            con = iState.Connection(copy.deepcopy(ip), copy.deepcopy(self.auth_queue), self.log_file)
            while not con.bQuit:
                con.run()
            
            self.log_file.write("\r\n\r\n!#*************************************#!")
            self.log_file.write("\r\n\r\n")

            con.exit()
            del con
