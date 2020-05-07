"""Exposes functionality for manipulating ELF files
"""
import mmap
import os
import subprocess

from elftools.elf.constants import P_FLAGS, E_FLAGS
from elftools.elf.constants import SHN_INDICES
from elftools.elf.descriptions import describe_e_type
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from termcolor import colored

from ..asm.asm import *
from logging import getLogger
from collections import namedtuple

log = getLogger(__name__)

__all__ = ['load', 'ELF']

Function = namedtuple('Function', 'address size')



def force_bytes(s):
    """force_bytes(s) -> bytes

    Ensures the given argument is of type bytes

    Example:

        >>> force_bytes(b'abc')
        b'abc'
        >>> force_bytes('abc')
        b'abc'
        >>> force_bytes(1)
        Traceback (most recent call last):
            ...
        TypeError: Expecting a value of type bytes or str, got 1
    """
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode('utf8')
    else:
        raise TypeError('Expecting a value of type bytes or str, got %r' % s)

def load(*args, **kwargs):
    """Compatibility wrapper for pwntools v1"""
    return ELF(*args, **kwargs)


class dotdict(dict):
    def __getattr__(self, name):
        return self[name]


class ELF(ELFFile):
    """Encapsulates information about an ELF file.

    :ivar path: Path to the binary on disk
    :ivar symbols:  Dictionary of {name: address} for all symbols in the ELF
    :ivar plt:      Dictionary of {name: address} for all functions in the PLT
    :ivar got:      Dictionary of {name: address} for all function pointers in the GOT
    :ivar libs:     Dictionary of {path: address} for each shared object required to load the ELF

    Example:

        .. code-block:: python

           bash = ELF(which('bash'))
           hex(bash.symbols[b'read'])
           # 0x41dac0
           hex(bash.plt[b'read'])
           # 0x41dac0
           u32(bash.read(bash.got[b'read'], 4))
           # 0x41dac6
           print disasm(bash.read(bash.plt[b'read'], 16), arch='amd64')
           # 0:   ff 25 1a 18 2d 00       jmp    QWORD PTR [rip+0x2d181a]        # 0x2d1820
           # 6:   68 59 00 00 00          push   0x59
           # b:   e9 50 fa ff ff          jmp    0xfffffffffffffa60
    """

    def __init__(self, path):
        # elftools uses the backing file for all reads and writes
        # in order to permit writing without being able to write to disk,
        # mmap() the file.
        self.file = open(path, 'rb')
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

        super(ELF, self).__init__(self.mmap)

        #: Path to the file
        self.path = os.path.abspath(path)

        #: Architecture of the file
        self.arch = self.get_machine_arch().lower()

        #: Endianness of the file
        self.endian = {
            'ELFDATANONE': 'little',
            'ELFDATA2LSB': 'little',
            'ELFDATA2MSB': 'big'
        }[self['e_ident']['EI_DATA']]

        #: Bit-ness of the file
        self.bits = self.elfclass
        self.bytes = self.bits // 8

        if self.arch == 'mips':
            if self.header['e_flags'] & E_FLAGS.EF_MIPS_ARCH_64 \
                    or self.header['e_flags'] & E_FLAGS.EF_MIPS_ARCH_64R2:
                self.arch = 'mips64'
                self.bits = 64

        self._populate_got_plt()
        self._populate_symbols()
        self._populate_functions()

        if self.elftype == 'DYN':
            self._address = 0
        else:
            self._address = min(filter(bool, (s.header.p_vaddr for s in self.segments)))
        self.load_addr = self._address


        print(colored("[*] ", "magenta", attrs=['bold']) + '{}'.format(self.path))


    def __repr__(self):
        return "ELF(%r)" % self.path

    def get_machine_arch(self):
        return {
            'EM_X86_64': 'amd64',
            'EM_386': 'i386',
            'EM_486': 'i386',
            'EM_ARM': 'arm',
            'EM_AARCH64': 'aarch64',
            'EM_MIPS': 'mips',
            'EM_PPC': 'powerpc',
            'EM_PPC64': 'powerpc64',
            'EM_SPARC32PLUS': 'sparc',
            'EM_SPARCV9': 'sparc64',
            'EM_IA_64': 'ia64'
        }.get(self['e_machine'], self['e_machine'])

    @property
    def entry(self):
        """Entry point to the ELF"""
        return self.address + (self.header.e_entry - self.load_addr)
    entrypoint = entry
    start = entry

    @property
    def elfclass(self):
        """ELF class (32 or 64).

        .. note::
            Set during ``ELFFile._identify_file``
        """
        return self._elfclass

    @elfclass.setter
    def elfclass(self, newvalue):
        self._elfclass = newvalue

    @property
    def elftype(self):
        """ELF type (EXEC, DYN, etc)"""
        return describe_e_type(self.header.e_type).split()[0]

    @property
    def segments(self):
        """A list of all segments in the ELF"""
        return list(self.iter_segments())

    @property
    def sections(self):
        """A list of all sections in the ELF"""
        return list(self.iter_sections())

    @property
    def dwarf(self):
        """DWARF info for the elf"""
        return self.get_dwarf_info()

    @property
    def sym(self):
        return self.symbols

    @property
    def address(self):
        """Address of the lowest segment loaded in the ELF.
        When updated, cascades updates to segment vaddrs, section addrs, symbols, plt, and got.

        Examples:

            >>> bash = ELF(which('bash'))
            >>> old = bash.symbols[b'read']
            >>> bash.address += 0x1000
            >>> bash.symbols[b'read'] == old + 0x1000
            True
        """
        return self._address

    @address.setter
    def address(self, new):
        delta = new - self._address
        update = lambda x: x + delta

        self.symbols = dotdict({k: update(v) for k, v in self.symbols.items()})
        self.plt = dotdict({k: update(v) for k, v in self.plt.items()})
        self.got = dotdict({k: update(v) for k, v in self.got.items()})

        self._address = update(self.address)

    def section(self, name):
        """Gets data for the named section

        Arguments:
            name(bytes): Name of the section

        Returns:
            String containing the bytes for that section
        """
        return self.get_section_by_name(name).data()

    @property
    def rwx_segments(self):
        """Returns: list of all segments which are writeable and executable."""
        if not self.nx:
            return self.writable_segments

        wx = P_FLAGS.PF_X | P_FLAGS.PF_W
        return [s for s in self.segments if s.header.p_flags & wx == wx]

    @property
    def executable_segments(self):
        """Returns: list of all segments which are executable."""
        if not self.nx:
            return list(self.segments)

        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_X]

    @property
    def writable_segments(self):
        """Returns: list of all segments which are writeable"""
        return [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_W]

    @property
    def non_writable_segments(self):
        """Returns: list of all segments which are NOT writeable"""
        return [s for s in self.segments if not s.header.p_flags & P_FLAGS.PF_W]

    @property
    def libc(self):
        """If the ELF imports any libraries which contain 'libc.so',
        and we can determine the appropriate path to it on the local
        system, returns an ELF object pertaining to that libc.so.

        Otherwise, returns ``None``.
        """
        for lib in self.libs:
            if '/libc.' in lib or '/libc-' in lib:
                return ELF(lib)


    def _populate_functions(self):
        """Builds a dict of 'functions' (i.e. symbols of type 'STT_FUNC')
        by function name that map to a tuple consisting of the func address and size
        in bytes.
        """
        self.functions = {}

        for sec in self.sections:
            if not isinstance(sec, SymbolTableSection):
                continue

            for sym in sec.iter_symbols():
                # Avoid duplicates
                if sym.name in self.functions:
                    continue

                if sym.entry.st_info['type'] == 'STT_FUNC' and sym.entry.st_size != 0:
                    name = sym.name
                    if name not in self.symbols:
                        continue
                    addr = self.symbols[name]
                    size = sym.entry.st_size
                    self.functions[name] = Function(addr, size)

    def _populate_symbols(self):
        """
        Examples:

            >>> bash = ELF(which('bash'))
            >>> bash.symbols[b'_start'] == bash.header.e_entry
            True
        """
        # By default, have 'symbols' include everything in the PLT.
        #
        # This way, elf.symbols[b'write'] will be a valid address to call
        # for write().
        self.symbols = dotdict(self.plt)

        for section in self.sections:
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                if not symbol.entry.st_value:
                    continue

                self.symbols[symbol.name.encode('ascii')] = symbol.entry.st_value

        # Add 'plt.foo' and 'got.foo' to the symbols for entries,
        # iff there is no symbol for that address
        for sym, addr in self.plt.items():
            if addr not in self.symbols.values():
                self.symbols[b'plt.' + sym] = addr

        for sym, addr in self.got.items():
            if addr not in self.symbols.values():
                self.symbols[b'got.' + sym] = addr

    def _populate_got_plt(self):
        """Loads the GOT and the PLT symbols and addresses.

        The following doctest checks the valitidy of the addresses.
        This assumes that each GOT entry points to its PLT entry,
        usually +6 bytes but could be anywhere within 0-16 bytes.

        Examples:

            >>> from pwnlib.util.packing import unpack
            >>> bash = ELF(which('bash'))
            >>> def validate_got_plt(sym):
            ...     got = bash.got[sym]
            ...     plt = bash.plt[sym]
            ...     got_addr = unpack(bash.read(got, bash.elfclass // 8), bash.elfclass)
            ...     return got_addr in range(plt, plt + 0x10)
            ...
            >>> all(map(validate_got_plt, bash.got.keys()))
            True
        """
        plt = self.get_section_by_name('.plt')
        got = self.get_section_by_name('.got')

        self.got = {}
        self.plt = {}

        if not plt:
            return

        # Find the relocation section for PLT
        try:
            rel_plt = next(s for s in self.sections if
                           s.header.sh_info == self.sections.index(plt) and
                           isinstance(s, RelocationSection))
        except StopIteration:
            # Evidently whatever android-ndk uses to build binaries zeroes out sh_info for rel.plt
            rel_plt = self.get_section_by_name('.rel.plt') or self.get_section_by_name('.rela.plt')

        if not rel_plt:
            log.warning("Couldn't find relocations against PLT to get symbols")
            return

        if rel_plt.header.sh_link != SHN_INDICES.SHN_UNDEF:
            # Find the symbols for the relocation section
            sym_rel_plt = self.sections[rel_plt.header.sh_link]

            # Populate the GOT
            for rel in rel_plt.iter_relocations():
                sym_idx = rel.entry.r_info_sym
                symbol = sym_rel_plt.get_symbol(sym_idx)
                name = symbol.name.encode('ascii')
                self.got[name] = rel.entry.r_offset

        # Depending on the architecture, the beginning of the .plt will differ
        # in size, and each entry in the .plt will also differ in size.
        offset = None
        multiplier = None

        # Map architecture: offset, multiplier
        header_size, entry_size = {
            'i386': (0x10, 0x10),
            'amd64': (0x10, 0x10),
            'arm': (0x14, 0xC),
            'aarch64': (0x20, 0x20),
        }.get(self.arch, (0, 0))

        # Based on the ordering of the GOT symbols, populate the PLT
        for i, (addr, name) in enumerate(sorted((addr, name)
                                                for name, addr in self.got.items())):
            self.plt[name] = plt.header.sh_addr + header_size + i * entry_size

    def search(self, needle, writable=False):
        """search(needle, writable=False) -> int generator

        Search the ELF's virtual address space for the specified string.

        Arguments:
            needle(bytes, str): String to search for.
            writable(bool): Search only writable sections.

        Returns:
            An iterator for each virtual address that matches.

        Examples:

            >>> bash = ELF(which('bash'))
            >>> bash.address + 1 == next(bash.search('ELF'))
            True

            >>> sh = ELF(which('bash'))
            >>> # /bin/sh should only depend on libc
            >>> libc_path = [key for key in sh.libs.keys() if 'libc' in key][0]
            >>> libc = ELF(libc_path)
            >>> # this string should be in there because of system(3)
            >>> len(list(libc.search('/bin/sh'))) > 0
            True
        """
        needle = misc.force_bytes(needle)
        load_address_fixup = (self.address - self.load_addr)

        if writable:
            segments = self.writable_segments
        else:
            segments = self.segments

        for seg in segments:
            addr = seg.header.p_vaddr
            data = seg.data()
            offset = 0
            while True:
                offset = data.find(needle, offset)
                if offset == -1:
                    break
                yield (addr + offset + load_address_fixup)
                offset += 1

    def offset_to_vaddr(self, offset):
        """Translates the specified offset to a virtual address.

        Arguments:
            offset(int): Offset to translate

        Returns:
            Virtual address which corresponds to the file offset, or None

        Examples:

            >>> bash = ELF(which('bash'))
            >>> bash.address == bash.offset_to_vaddr(0)
            True
            >>> bash.address += 0x123456
            >>> bash.address == bash.offset_to_vaddr(0)
            True
        """
        load_address_fixup = (self.address - self.load_addr)

        for segment in self.segments:
            begin = segment.header.p_offset
            size = segment.header.p_filesz
            end = begin + size
            if begin <= offset and offset <= end:
                delta = offset - begin
                return segment.header.p_vaddr + delta + load_address_fixup
        return None

    def vaddr_to_offset(self, address):
        """Translates the specified virtual address to a file address

        Arguments:
            address(int): Virtual address to translate

        Returns:
            Offset within the ELF file which corresponds to the address,
            or None.

        Examples:

            >>> bash = ELF(which('bash'))
            >>> 0 == bash.vaddr_to_offset(bash.address)
            True
            >>> bash.address += 0x123456
            >>> 0 == bash.vaddr_to_offset(bash.address)
            True
        """
        load_address = address - self.address + self.load_addr

        for segment in self.segments:
            begin = segment.header.p_vaddr
            size = segment.header.p_memsz
            end = begin + size
            if begin <= load_address and load_address <= end:
                delta = load_address - begin
                return segment.header.p_offset + delta

        log.warning("Address %#x does not exist in %s" % (address, self.file.name))
        return None

    def read(self, address, count):
        """Read data from the specified virtual address

        Arguments:
            address(int): Virtual address to read
            count(int): Number of bytes to read

        Returns:
            A string of bytes, or None

        Examples:

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address + 1, 3)
            b'ELF'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            old = self.stream.tell()
            self.stream.seek(offset)
            data = self.stream.read(count)
            self.stream.seek(old)
            return data

        return b''

    def write(self, address, data):
        """Writes data to the specified virtual address

        Arguments:
            address(int): Virtual address to write
            data(bytes): Bytes to write

        Note::
            This routine does not check the bounds on the write to ensure
            that it stays in the same segment.

        Examples:

            >>> bash = ELF(which('bash'))
            >>> bash.read(bash.address + 1, 3)
            b'ELF'
            >>> bash.write(bash.address, b"HELO")
            >>> bash.read(bash.address, 4)
            b'HELO'
        """
        offset = self.vaddr_to_offset(address)

        if offset is not None:
            old = self.stream.tell()
            self.stream.seek(offset)
            self.stream.write(data)
            self.stream.seek(old)

        return None

    def save(self, path):
        """Save the ELF to a file

        Examples:

            >>> bash = ELF(which('bash'))
            >>> bash.save('/tmp/bash_copy')
            >>> copy = open('/tmp/bash_copy', 'rb')
            >>> bash = open(which('bash'), 'rb')
            >>> bash.read() == copy.read()
            True
        """
        old = self.stream.tell()

        with open(path, 'wb+') as fd:
            self.stream.seek(0)
            fd.write(self.get_data())

        self.stream.seek(old)

    def get_data(self):
        """Retrieve the raw data from the ELF file.

        Examples:

            >>> bash = ELF(which('bash'))
            >>> fd = open(which('bash'), 'rb')
            >>> bash.get_data() == fd.read()
            True
        """
        old = self.stream.tell()
        self.stream.seek(0)
        data = self.stream.read(self.stream.size())
        self.stream.seek(old)
        return data

    @property
    def data(self):
        return self.get_data()

    def disasm(self, address, n_bytes):
        """Returns a string of disassembled instructions at
        the specified virtual memory address"""
        arch = self.arch
        if self.arch == 'arm' and address & 1:
            arch = 'thumb'
            address -= 1
        return disasm(self.read(address, n_bytes), vma=address, arch=arch)

    def asm(self, address, assembly):
        """Assembles the specified instructions and inserts them
        into the ELF at the specified address.

        The resulting binary can be saved with ELF.save()
        """
        binary = asm(assembly, vma=address)
        self.write(address, binary)

    def bss(self, offset=0):
        """Returns an index into the .bss segment"""
        orig_bss = self.get_section_by_name('.bss').header.sh_addr
        curr_bss = orig_bss - self.load_addr + self.address
        return curr_bss + offset

    def __repr__(self):
        return "ELF(%r)" % self.path

    def dynamic_by_tag(self, tag):
        dt = None
        dynamic = self.get_section_by_name('.dynamic')

        if not dynamic:
            return None

        try:
            dt = next(t for t in dynamic.iter_tags() if tag == t.entry.d_tag)
        except StopIteration:
            pass

        return dt

    def dynamic_string(self, offset):
        dt_strtab = self.dynamic_by_tag('DT_STRTAB')

        if not dt_strtab:
            return None

        address = dt_strtab.entry.d_ptr + offset
        string = b''
        while b'\x00' not in string:
            string += self.read(address, 1)
            address += 1
        return string.rstrip(b'\x00')

    @property
    def relro(self):
        if self.dynamic_by_tag('DT_BIND_NOW'):
            return "Full"

        if any('GNU_RELRO' in str(s.header.p_type) for s in self.segments):
            return "Partial"
        return None

    @property
    def nx(self):
        if not any('GNU_STACK' in str(seg.header.p_type) for seg in self.segments):
            return False

        # Can't call self.executable_segments because of dependency loop.
        exec_seg = [s for s in self.segments if s.header.p_flags & P_FLAGS.PF_X]
        return not any('GNU_STACK' in seg.header.p_type for seg in exec_seg)

    @property
    def execstack(self):
        return not self.nx

    @property
    def canary(self):
        return b'__stack_chk_fail' in self.symbols

    @property
    def packed(self):
        return b'UPX!' in self.get_data()

    @property
    def pie(self):
        return self.elftype == 'DYN'
    aslr = pie

    @property
    def rpath(self):
        dt_rpath = self.dynamic_by_tag('DT_RPATH')

        if not dt_rpath:
            return None

        return self.dynamic_string(dt_rpath.entry.d_ptr)

    @property
    def runpath(self):
        dt_runpath = self.dynamic_by_tag('DT_RUNPATH')

        if not dt_runpath:
            return None

        return self.dynamic_string(dt_rpath.entry.d_ptr)

    def checksec(self, banner=True):
        red = lambda s: colored(s, "red")
        green = lambda s: colored(s, "green")
        yellow = lambda s: colored(s, "yellow")

        res = [
            "RELRO:".ljust(10) + {
                'Full': green("Full RELRO"),
                'Partial': yellow("Partial RELRO"),
                None: red("No RELRO")
            }[self.relro],
            "Stack:".ljust(10) + {
                True: green("Canary found"),
                False: red("No canary found")
            }[self.canary],
            "NX:".ljust(10) + {
                True: green("NX enabled"),
                False: red("NX disabled"),
            }[self.nx],
            "PIE:".ljust(10) + {
                True: green("PIE enabled"),
                False: red("No PIE")
            }[self.pie]
        ]

        # Are there any RWX areas in the binary?
        #
        # This will occur if NX is disabled and *any* area is
        # RW, or can expressly occur.
        rwx = self.rwx_segments

        if self.nx and rwx:
            res.append("RWX:".ljust(10) + red("Has RWX segments"))

        if self.rpath:
            res.append("RPATH:".ljust(10) + red(repr(self.rpath)))

        if self.runpath:
            res.append("RUNPATH:".ljust(10) + red(repr(self.runpath)))

        if self.packed:
            res.append('Packer:'.ljust(10) + red("Packed with UPX"))

        if self.fortify:
            res.append("FORTIFY:".ljust(10) + green("Enabled"))

        if self.asan:
            res.append("ASAN:".ljust(10) + green("Enabled"))

        if self.msan:
            res.append("MSAN:".ljust(10) + green("Enabled"))

        if self.ubsan:
            res.append("UBSAN:".ljust(10) + green("Enabled"))

        return '\n'.join(res)

    @property
    def buildid(self):
        section = self.get_section_by_name('.note.gnu.build-id')
        if section:
            return section.data()[16:]
        return None

    @property
    def fortify(self):
        if any(s.endswith(b'_chk') for s in self.plt):
            return True
        return False

    @property
    def asan(self):
        return any(s.startswith(b'__asan_') for s in self.symbols)

    @property
    def msan(self):
        return any(s.startswith(b'__msan_') for s in self.symbols)

    @property
    def ubsan(self):
        return any(s.startswith(b'__ubsan_') for s in self.symbols)

    def p64(self, address, data, *a, **kw): return self.write(address, packing.p64(data, *a, **kw))

    def p32(self, address, data, *a, **kw): return self.write(address, packing.p32(data, *a, **kw))

    def p16(self, address, data, *a, **kw): return self.write(address, packing.p16(data, *a, **kw))

    def p8(self, address, data, *a, **kw): return self.write(address, packing.p8(data, *a, **kw))

    def pack(self, address, data, *a, **kw): return self.write(address, packing.pack(data, *a, **kw))

    def u64(self, address, *a, **kw): return packing.u64(self.read(address, 8), *a, **kw)

    def u32(self, address, *a, **kw): return packing.u32(self.read(address, 4), *a, **kw)

    def u16(self, address, *a, **kw): return packing.u16(self.read(address, 2), *a, **kw)

    def u8(self, address, *a, **kw): return packing.u8(self.read(address, 1), *a, **kw)

    def unpack(self, address, *a, **kw): return packing.unpack(self.read(address), *a, **kw)

    def string(self, address):
        data = b''
        while True:
            c = self.read(address, 1)
            if not c:
                return b''
            if c == b'\x00':
                return data
            data += c
            address += 1
