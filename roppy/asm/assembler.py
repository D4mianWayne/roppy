from roppy.misc.utils import str2bytes
from keystone import *
from capstone import *


cmd = {
       
       'i386': {
        "disasm": Cs(CS_ARCH_X86, CS_MODE_32),
        "asm"   : Ks(KS_ARCH_X86, KS_MODE_32)
        },

        'x86-64': {
            "disasm" : Cs(CS_ARCH_X86, CS_MODE_64),
            "asm"    : Ks(KS_ARCH_X86, KS_MODE_64)
        }
    }

def assemble(s, arch):
    if arch in cmd:
        assembler = cmd[arch]["asm"]
    else:
        raise Exception("unsupported architecture: %r" % arch)

    if isinstance(s, str):
        s = str2bytes(s)

    encoding, count = assembler.asm(s)
    res = b""
    for ins in encoding:
        res += bytes([ins])
    return res





def disasm(blob, arch, vma=0x0):
    if arch in cmd:
        md = cmd[arch]["disasm"]
    else:
        raise Exception("Unsupported Architecture: %r" % arch)
    res = ""
    for i in md.disasm(blob, vma):
        res += "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
    return res
