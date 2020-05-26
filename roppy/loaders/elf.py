from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.constants import SHN_INDICES
import os
from roppy.log import log
from roppy.misc import str2bytes, bytes2str
import mmap

class dotdict(dict):
    def __getattr__(self, name):
        return self[name]

class ELF(ELFFile):
    """
    `ELF` class encapsulates the `pyelftools.elf.elffile`
     for providing a simplistic way to access the ELF file
     symbols, sections, strings which saves the time for 
     resolving the address.
     """
    def __init__(self, path):
        self.path = os.path.abspath(path)

        self.file    = open(self.path,'rb')
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)
        super(ELF, self).__init__(self.mmap)
        """ Encapsulates the `ELF` """
        
        self.initialize()

    def initialize(self):
        """
        Initializing the ELF class by loading 
        the information about of the sections, plt,
        got and function addresses
        """
        log.info("Analyzing {}".format(self.path))

        self._pie    = 'DYN' in self.header.e_type
        self.arch   = self.get_machine_arch().lower()

        
        if self._pie:
            self.base   = 0
        else:
            self.base = min(filter(bool, (s.header.p_vaddr for s in self.iter_segments())))
        
        self.__section                  = self.init_sections()
        self.__got                      = self.init_got()
        self.__plt                      = self.init_plt()
        self.__symbol, self.__function  = self.init_symbols()

    def init_sections(self):
        """ Initializing sections of the ELF file """
        section = dict()
        self.__list_sections = list(self.iter_sections())
            
        for sec in self.__list_sections:
            section[sec.name]  = sec.header.sh_addr

        return section

    def init_got(self):
        """ Initializing the Global Offset Table """
        addr_plt = self.get_section_by_name(".plt")
        got = dict()
        try:
            rel_plt = next(s for s in self.__list_sections if
                           s.header.sh_info == self.__list_sections.index(addr_plt) and
                           isinstance(s, RelocationSection))
        except StopIteration:
            rel_plt = self.get_section_by_name('.rel.plt') or self.get_section_by_name('.rela.plt')

        if not rel_plt:
            log.warn("Couldn't find relocations against PLT to get symbols")
            return

        if rel_plt.header.sh_link != SHN_INDICES.SHN_UNDEF:
            # Find the symbols for the relocation section
            sym_rel_plt = self.__list_sections[rel_plt.header.sh_link]

            # Populate the GOT by iterating over the relocation section.
            for rel in rel_plt.iter_relocations():
                sym_idx = rel.entry.r_info_sym
                symbol = sym_rel_plt.get_symbol(sym_idx)
                name = symbol.name
                got[name] = rel.entry.r_offset
                
        return got

    def init_plt(self):
        """ Initializing the Procedure Linkage Table """
        addr_plt = self.get_section_by_name('.plt')
        if self.arch in ('x86','x64','amd64','80386','x86-64'):
            header_size, entry_size = 0x10, 0x10

        '''
        sec_plt     = self.elf.get_section_by_name('.plt')
        plt = {u'resolve' : sec_plt.header.sh_addr}
        addr_plt_entry = sec_plt.header.sh_addr + header_size
        '''
        plt = {}
        for i, (addr, name) in enumerate(sorted((addr, name)
                                                for name, addr in self.__got.items())):
            plt[name] = addr_plt.header.sh_addr + header_size + i * entry_size

        return plt

    
    def init_symbols(self):
        """ Initializing the symbols from the ELF file """
        symbol      = dict()
        function    = dict()

        for sec in self.__list_sections:
            if not isinstance(sec, SymbolTableSection):
                continue
            
            for sym in sec.iter_symbols():
                if sym.entry.st_value:
                    if sym.entry.st_info['type'] == 'STT_FUNC':
                        function[sym.name]  = sym.entry.st_value
                    else:
                        symbol[sym.name]    = sym.entry.st_value

        return symbol, function


    @property
    def address(self):
        """ Returns the base address of the ELF file """
        return self.base

    @address.setter
    def address(self, new):
        """ Updates the address of an ELF file """
        delta = new - self.base
        update = lambda x: x + delta

        self.__symbol = dotdict({k: update(v) for k, v in self.__symbol.items()})
        self.__function = dotdict({k: update(v) for k, v in self.__function.items()})
        self.__plt = dotdict({k: update(v) for k, v in self.__plt.items()})
        self.__got = dotdict({k: update(v) for k, v in self.__got.items()})
        self.__section = dotdict({k: update(v) for k, v in self.__section.items()})

        self.base = update(self.address)
    

    def search(self, data, *section):
        """ Helps in searching string from the binary """
        if len(section):
            section = list(self.elf.get_section_by_name(k) for k in section)
        else:
            section = self.__list_sections

        for sec in section:
            if data in sec.data():
                return self.base + sec.header.sh_addr + sec.data().find(data)

            
        return None

    def section(self, name=None):
        """ Returns the section address """
        if self._pie and not self.base:
            log.warn('ELF : Base address not set')
            
        if name is None:
            return self.__section
        elif name not in self.__section:
            log.error('ELF : section "%s" not found' % name)
            return None
        
        return self.__section[name]

    def plt(self, name=None):
        """ Returns the PLT address """
        if name is None:
            return self.__plt
        elif name not in self.__plt:
            log.error('ELF : plt "%s" not found' % name)
            return None
        
        return self.__plt[name]

    def got(self, name=None):
        """ Returns the GOT address """
        if name is None:
            return self.__got
        elif name not in self.__got:
            log.error('ELF : got "%s" not found' % name)
            return None
        
        return self.__got[name]
    
    def function(self, name=None):
        """ Returns the function address """
        if name is None:
            return self.__function
        elif name not in self.__function:
            log.error('ELF : function "%s" not found' % name)
            return None
        
        return self.__function[name]

    def symbol(self, name=None):
        """ Returns the symbol address """
        if name is None:
            return self.__symbol
        elif name not in self.__symbol:
            log.error('ELF : symbol "%s" not found' % name)
            return None
        
        return self.__symbol[name]
