from collections import *
from functools import *
from glob import glob
from os import path
from roppylib.context import *
from roppylib.log import getLogger

log = getLogger(__name__)


class LibcSearcher2:
    def __init__(self, db_path=context.libc_database_path):
        if db_path is None:
            log.error("No path found, please define a path with `context.libc_database_path = '/path'`")
        self.__lookup = defaultdict(set)
        self.__db = defaultdict(dict)
        for symbol_file in glob(path.join(db_path, "*.symbols")):
            libc_id = path.splitext(path.basename(symbol_file))[0]
            with open(symbol_file) as f:
                for line in f.read().splitlines():
                    symbol, addr = line.split(' ')
                    self.__lookup[(symbol, int(addr, 16))].add(libc_id)
                    self.__lookup[(symbol, int(addr[-3:], 16))].add(libc_id)
                    self.__db[libc_id][symbol] = int(addr, 16)

    def search(self, cond):
        result = list(filter(len, [self.__lookup[c] for c in cond]))
        return list(reduce(lambda x, y: x.intersection(y), result)) if result is not None and len(result) else None

    def search_simple(self, symbol, address):
        return self.search([(symbol, address & 0xfff)])

    def dump(self, libc_id, func):
        return self.__db[libc_id][func]

    def dumps(self, libc_id, func, addr):
        offset = addr - self.__db[libc_id][func]
        return lambda f: offset + self.__db[libc_id][f]
