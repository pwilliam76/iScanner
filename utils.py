#!/usr/bin/env python
#encoding:utf-8

def ip2num(ip, bigendian=True):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3] & 0xffffffff


def num2ip(num, bigendian=True):
    return '%s.%s.%s.%s' % ((num >> 24) & 0xff, (num >> 16) & 0xff, (num >> 8) & 0xff, num & 0xff)