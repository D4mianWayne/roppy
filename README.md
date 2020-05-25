# roppy


A Pwning toolkit which allows you to interact with local process and network and lighten up your work during pwn. I made this in order to get the better understanding of python so that I could learn pwning more and this is one of my best project so far.


### Documentation

Although I'm working on do a documentation readthedocs but working alone on this project is very tiresome so I have to work 2x times of usual work and on the side work I have to learn about Pwning more.

For the time being, the documentation can be found 

##### Importing `roppy`

Import roppy functions as global namespaces:-

```python
Python 3.8.2 (default, Apr 27 2020, 15:53:34) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from roppy import *
```

This will import all the `roppy` functions as global namespaces.

##### Spawn a process


To spawn a local process:-

```python
>>> p = process("/bin/bash")
[+] Successfully started process. PID - 44939
```

This will start a local process and allow you to interact with it.

#### Interacting with the process

To interact with the running process:-

```python
>>> p.sendline("echo Hello World")
>>> p.recvline()
b'Hello World'
>>> p.sendline("id")
>>> p.recvline()
b'uid=1000(robin) gid=1000(robin)'
>>> p.sendline("echo Pwning the World")
>>> p.recvuntil("the")
b'Pwning the'
>>> p.recvline()
b' World'
>>> 
```

Now to spawn an interactive shell:-

```python
>>> p.interactive()
[+] Switching to Interaactive mode
$ ls
buf  buf_exp.py  examples  README.md  roppy  setup.py
$ echo "Hello World"
Hello World
$ exit
[*] EOF while reading in Interactive.
>>> p.close()
[*] Process /bin/bash stopped with exit code 0. PID - 44939
```

##### Packing and Unpacking numbers

To pack and unpack numbers:-

```r
>>> p32(0xdeadbeef)
b'\xef\xbe\xad\xde'
>>> p64(0xdeadbeef)
b'\xef\xbe\xad\xde\x00\x00\x00\x00'
>>> data = p32(0xdeadbeef)
>>> data
b'\xef\xbe\xad\xde'
>>> u32(data)
3735928559
>>> hex(u32(data))
'0xdeadbeef'
>>> data = p64(0xdeadbeef)
>>> data
b'\xef\xbe\xad\xde\x00\x00\x00\x00'
>>> u64(data)
3735928559
>>> hex(u64(data))
'0xdeadbeef'
```

# Note

This is in active development, so please be careful and report the issues to me and once done with beta release, there will be a documentation.
