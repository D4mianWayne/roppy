#-*- coding:utf-8 -*-

from roppylib.libformatstr.pattern import msfpattern
from roppylib.util.misc import tobytes
from binascii import unhexlify


def guess_argnum(result, buffer_size, start_index=1):
    """
    Guess the offset of the pattern
    for the format string
    """
    pattern_size = buffer_size // 8 
    pat = msfpattern(pattern_size * 4)
    if result[:len(pat)] != pat:
        return None
    result = result[len(pat):].replace("(nil)", "0x00000000").rstrip("X")

    parts = result.split("0x")[1:]
    for i, p in enumerate(parts):
        p = unhexlify(p.rjust(8, "0").encode("utf-8"))[::-1]
        p = tobytes(p) 
        if p in pat:
            block_index = pat.find(p)
            padding = block_index % 4

            argnum = start_index + i * (pattern_size - 1)
            argnum -= block_index // 4
            return argnum, padding
    return None


