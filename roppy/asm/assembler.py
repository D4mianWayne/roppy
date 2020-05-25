from roppy.misc.utils import str2bytes
from roppy.log import log
from keystone import *
from capstone import *


cmd = {
       
       'i386': {
        "disasm": Cs(CS_ARCH_X86, CS_MODE_32),
        "asm"   : Ks(KS_ARCH_X86, KS_MODE_32)
        },

        'amd64': {
            "disasm" : Cs(CS_ARCH_X86, CS_MODE_64),
            "asm"    : Ks(KS_ARCH_X86, KS_MODE_64)
        }
    }

def assemble(s, arch):
    """
    Assemble a string of opcode of given architecture
    Example:
           
           >>> from roppy import *
           >>> sc = '''
           ...        xor    eax,eax
           ...        push   eax
           ...        push   0x68732f2f
           ...        push   0x6e69622f
           ...        mov    ebx,esp
           ...        push   eax
           ...        push   ebx
           ...        mov    ecx, esp
           ...        mov    al, 0xb
           ...        int    $0x80
           ...      '''
           >>> 
           >>> arch = "i386"
           >>> assemble(sc, arch)
           b'1\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b'
           >>> CODE = b'1\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b'
           >>> print(disasm(CODE, arch, 0x4000))
           0x4000:	xor	eax, eax
           0x4002:	push	eax
           0x4003:	push	0x68732f2f
           0x4008:	push	0x6e69622f
           0x400d:	mov	ebx, esp
           0x400f:	push	eax
           0x4010:	push	ebx
           0x4011:	mov	ecx, esp
           0x4013:	mov	al, 0xb
           >>> 
        
    It also supports 64 bit assembly which can be specified by passing `amd64` to arch paramter.
        Example:
           >>> arch = "amd64"
           >>> CODE = '''
           ...      xor rax, rax
           ...      push rax
           ...      xor rdx, rdx
           ...      xor rsi, rsi
           ...      movabs rbx, 0x68732f2f6e69622f
           ...      push rbx
           ...      push rsp
           ...      pop rdi
           ...      mov al, 0x3b
           ...      syscall
           ... '''
           >>> print(assemble(CODE, arch))
           b'H1\xc0PH1\xd2H1\xf6H\xbb/bin//shST_\xb0;\x0f\x05'
           >>> CODE = b'\x48\x31\xc0\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
           >>> print(disasm(CODE, arch, 0x4000))
           0x4000:	xor	rax, rax
           0x4003:	push	rax
           0x4004:	xor	rdx, rdx
           0x4007:	xor	rsi, rsi
           0x400a:	movabs	rbx, 0x68732f2f6e69622f
           0x4014:	push	rbx
           0x4015:	push	rsp
           0x4016:	pop	rdi
           0x4017:	mov	al, 0x3b
           0x4019:	syscall	
           >>> 
    """
    if arch in cmd:
        assembler = cmd[arch]["asm"]
    else:
        raise Exception("unsupported architecture: %r" % arch)

    if isinstance(s, str):
        s = str2bytes(s)

    try:
        encoding, count = assembler.asm(s)
    except Exception as E:
        log.error(E)
    res = b""
    for ins in encoding:
        res += bytes([ins])
    return res





def disasm(blob, arch, vma=0x0):
    if arch in cmd:
        md = cmd[arch]["disasm"]
    else:
        raise Exception("Unsupported Architecture: %r" % arch)
    try:
        res = ""
        for i in md.disasm(blob, vma):
            res += "0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str)
        return res
    except Exception as E:
        log.error(E)
