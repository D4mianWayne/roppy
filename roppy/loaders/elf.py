from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os
from ..log import *


class ELF:
    """
    ELF Class to analyze the ELF attributes
    with the help of `pyelftools`.

    """
    def __init__(self, fpath, **args):

        self.fpath = os.path.abspath(fpath)
        if not os.path.exists(self.fpath):
            logger.error("{} does not exists.".format(self.fpath))
            return 
        
        self.__ELFFile              = ELFFile
        self.__symbolTableSection   = SymbolTableSection
        
        self.initialize(args)

    def initialize(self, args):
        """
        Initializing the objects
        for ELF class
        """

        logger.info("Analysing {}".format(self.fpath))

        self.elf    = self.__ELFFile(open(self.fpath,'rb'))

        self.pie    = 'DYN' in self.elf.header.e_type
        self.arch   = self.elf.get_machine_arch().lower()

        if self.pie:
            self.base = 0   
        else:
            self.base = min(filter(bool, (s.header.p_vaddr for s in self.elf.iter_segments())))
        
        self.__section                  = self.init_sections()
        self.__got                      = self.init_got()
        self.__plt                      = self.init_plt()
        self.__symbol, self.__function  = self.init_symbols()

        logger.info("Done analysing {}".format(self.fpath))
        


    def init_sections(self):
        """ Initializing sections """
        section = dict()
        
        self.__list_sections = list(self.elf.iter_sections())
            
        for sec in self.__list_sections:
            section[sec.name]  = sec.header.sh_addr


        return section

    def init_got(self):
        """ Initializing Global Offset Tablw """
        got = dict()
        name_rel_dyn = '.rel.dyn' if self.arch in ['x86', '80386'] else '.rela.dyn'
        name_rel_plt = '.rel.plt' if self.arch in ['x86', '80386'] else '.rela.plt'

        for name_rel in [name_rel_dyn, name_rel_plt]:               
            sec_rel = self.elf.get_section_by_name(name_rel)
            if sec_rel:
                sym_rel = self.__list_sections[sec_rel.header.sh_link]

                for rel in sec_rel.iter_relocations():
                    sym_idx = rel.entry.r_info_sym
                    sym     = sym_rel.get_symbol(sym_idx)
                    got[sym.name]  = rel.entry.r_offset
                
        return got

    def init_plt(self):
        """ Initializing Procedure Linkage Table """
        addr_plt = self.__section['.plt']
        if self.arch in ('x86','x64','amd64','80386','x86-64'):
            header_size, entry_size = 0x10, 0x10


        plt = {'resolve' : addr_plt}
        addr_plt_entry = addr_plt + header_size
        for name, addr in sorted(self.__got.items(), key=lambda x:x[1]):
            plt[name] = addr_plt_entry
            addr_plt_entry += entry_size

        return plt

    def init_symbols(self):
        """ Symbol Section Initialization """
        symbol      = dict()
        function    = dict()

        for sec in self.__list_sections:
            if not isinstance(sec, self.__symbolTableSection):
                continue
            
            for sym in sec.iter_symbols():
                if sym.entry.st_value:
                    if sym.entry.st_info['type'] == 'STT_FUNC':
                        function[sym.name]  = sym.entry.st_value
                    else:
                        symbol[sym.name]    = sym.entry.st_value

        return symbol, function
        

    def search(self, data, *section):
        if len(section):
            section = list(self.elf.get_section_by_name(k) for k in section)
        else:
            section = self.__list_sections

        for sec in section:
            if data in sec.data():
                return self.base + sec.header.sh_addr + sec.data().find(data)

        return None

    def section(self, name=None):
        if self.pie and not self.base:
            logger.warn('Base address not set')
            
        if name is None:
            return self.__section
        elif name not in self.__section:
            logger.error('Section "%s" not found' % name)
            return None
        
        return self.base + self.__section[name]

    def plt(self, name=None):
        if name is None:
            return self.__plt
        elif name not in self.__plt:
            logger.error('PLT "%s" not found' % name)
            return None
        
        return self.base + self.__plt[name]

    def got(self, name=None):
        if name is None:
            return self.__got
        elif name not in self.__got:
            logger.error('GOT "%s" not found' % name)
            return None
        
        return self.base + self.__got[name]
    
    def function(self, name=None):
        if name is None:
            return self.__function
        elif name not in self.__function:
            logger.error('Function "%s" not found' % name)
            return None
        
        return self.base + self.__function[name]

    def symbols(self, name=None):
        if name is None:
            return self.__symbol
        elif name not in self.__symbol:
            logger.error('Symbol "%s" not found' % name)
            return None
        
        return self.base + self.__symbol[name]

