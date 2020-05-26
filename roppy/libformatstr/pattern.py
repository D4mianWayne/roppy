#!/usr/bin/env python
#-*- coding:utf-8 -*-

import sys

def msfpattern(n):
    """msfpattern-like patterns"""
    def inc(alphas, indexes, i):
        indexes[i % 3] += 1
        if indexes[i % 3] >= len(alphas[i % 3]):
            indexes[i % 3] = 0
            inc(alphas, indexes, i-1)
        return

    alphas = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"]
    indexes = [0] * len(alphas)

    chars = []
    for i in range(n):
        chars.append(alphas[i % 3][indexes[i % 3]])
        if i % 3 == 2:
            inc(alphas, indexes, i)
    return "".join(chars)

def fmt_cylic(buffer_size, start_index=1, max_index=500):
    format_size = buffer_size // 2
    pattern_size = buffer_size // 8 
    
    index = start_index
    payload = msfpattern(pattern_size * 4)
    while True:
        fmt = "%" + str(index) + "$p"
        if len(payload) + len(fmt) > buffer_size:
            break
        payload += fmt
        index += pattern_size - 1
        if index > max_index:
            break
    return payload.ljust(buffer_size, "X")
