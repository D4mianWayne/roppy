from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os
from roppy.log import log


class dotdict(dict):
    def __getattr__(self, name):
        return self[name]

class ELF:
    def __init__(self, path, mode='elftools', **args):
        self.path = os.path.abspath(path)
        self.__ELFFile              = ELFFile
        self.__symbolTableSection   = SymbolTableSection
        
        self.initialize(args)

    def initialize(self, args):
        log.info("Analyzing {}".format(self.path))

        self.elf    = self.__ELFFile(open(self.path,'rb'))

        self.pie    = 'DYN' in self.elf.header.e_type
        self.arch   = self.elf.get_machine_arch().lower()

        
        if self.pie:
            self.base   = 0
        else:
            self.base = min(filter(bool, (s.header.p_vaddr for s in self.elf.iter_segments())))
        
        self.__section                  = self.init_sections()
        self.__got                      = self.init_got()
        self.__plt                      = self.init_plt()
        self.__symbol, self.__function  = self.init_symbols()
        
        self.__list_gadgets             = self.init_ropgadget() if 'rop' in args and args['rop'] else None

    def init_sections(self):
        section = dict()
        self.__list_sections = list(self.elf.iter_sections())
            
        for sec in self.__list_sections:
            section[sec.name]  = sec.header.sh_addr

        return section

    def init_got(self):
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
        addr_plt = self.__section['.plt']
        if self.arch in ('x86','x64','amd64','80386','x86-64'):
            header_size, entry_size = 0x10, 0x10

        '''
        sec_plt     = self.elf.get_section_by_name('.plt')
        plt = {u'resolve' : sec_plt.header.sh_addr}
        addr_plt_entry = sec_plt.header.sh_addr + header_size
        '''
        plt = {'resolve' : addr_plt}
        addr_plt_entry = addr_plt + header_size
        for name, addr in sorted(self.__got.items(), key=lambda x:x[1]):
            plt[name] = addr_plt_entry
            addr_plt_entry += entry_size

        return plt

    
    def init_symbols(self):
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


    @property
    def address(self):
        return self.base

    @address.setter
    def address(self, new):
        delta = new - self.base
        update = lambda x: x + delta

        self.__symbol = dotdict({k: update(v) for k, v in self.__symbol.items()})
        self.__function = dotdict({k: update(v) for k, v in self.__function.items()})
        self.__plt = dotdict({k: update(v) for k, v in self.__plt.items()})
        self.__got = dotdict({k: update(v) for k, v in self.__got.items()})
        self.__section = dotdict({k: update(v) for k, v in self.__section.items()})

        self.base = update(self.address)
    

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
            log.warn('ELF : Base address not set')
            
        if name is None:
            return self.__section
        elif name not in self.__section:
            log.error('ELF : section "%s" not found' % name)
            return None
        
        return self.__section[name]

    def plt(self, name=None):
        if name is None:
            return self.__plt
        elif name not in self.__plt:
            log.error('ELF : plt "%s" not found' % name)
            return None
        
        return self.__plt[name]

    def got(self, name=None):
        if name is None:
            return self.__got
        elif name not in self.__got:
            log.error('ELF : got "%s" not found' % name)
            return None
        
        return self.__got[name]
    
    def function(self, name=None):
        if name is None:
            return self.__function
        elif name not in self.__function:
            log.error('ELF : function "%s" not found' % name)
            return None
        
        return self.__function[name]

    def symbol(self, name=None):
        if name is None:
            return self.__symbol
        elif name not in self.__symbol:
            log.error('ELF : symbol "%s" not found' % name)
            return None
        
        return self.__symbol[name]
