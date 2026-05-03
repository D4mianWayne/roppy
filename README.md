# roppy 🛠️

A modern Python pwning toolkit for binary exploitation, CTF challenges, and security research.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🚀 Features

- **Process & Network Tubes**: Seamlessly interact with local processes and remote services
- **ELF Binary Manipulation**: Easy access to PLT, GOT, symbols, and sections
- **Assembly & Disassembly**: Built-in assembler/disassembler for x86/x64 architectures
- **Format String Exploitation**: Dedicated library for format string vulnerabilities
- **ROP Utilities**: SROP (Sigreturn-Oriented Programming) frame building
- **Shellcode Generation**: Pre-built shellcode templates
- **Packing Utilities**: Convenient functions for packing/unpacking integers

## 📦 Installation

### From Source

```bash
git clone https://github.com/D4mianWayne/roppy.git
cd roppy
pip install -e .
```

### Using pip (once published)

```bash
pip install roppy
```

## 🎯 Quick Start

### Connecting to a Remote Service

```python
from roppy import *

# Connect to a remote challenge
p = remote("challenge.ctf.example", 1337)

# Receive until prompt
p.recvuntil(b"Enter input: ")

# Send payload
payload = b"A" * 64 + p64(0xdeadbeef)
p.sendline(payload)

# Interactive shell
p.interactive()
```

### Working with Local Processes

```python
from roppy import *

# Spawn a local process
p = process("./vulnerable_binary")

# Read ELF information
elf = ELF("./vulnerable_binary")
print(f"PLT: {hex(elf.plt('puts'))}")
print(f"GOT: {hex(elf.got('puts'))}")

# Send exploit
p.sendlineafter(b"Name: ", payload)

```

### Binary Analysis

```python
from roppy import *

# Load an ELF binary
elf = ELF("./binary")

# Access symbols and sections
print(f"Base Address: {hex(elf.address)}")
print(f"puts@plt: {hex(elf.plt('puts'))}")
print(f"puts@got: {hex(elf.got('puts'))}")

# Search for strings
bin_sh = elf.search(b"/bin/sh")
print(f"/bin/sh address: {hex(bin_sh)}")
```

### Assembly and Shellcode

```python
from roppy import *

# Assemble x64 shellcode
shellcode = assemble("""
    xor rax, rax
    push rax
    mov rbx, 0x68732f6e69622f
    push rbx
    mov rdi, rsp
    mov al, 59
    syscall
""", "amd64")

# Disassemble bytes
code = b"\x48\x31\xc0\x50"
print(disasm(code, "amd64", 0x400000))
```

## 📚 Core Components

| Module | Description |
|--------|-------------|
| `roppy.tubes` | Process and network communication (`process`, `remote`) |
| `roppy.loaders` | ELF binary parsing and manipulation (`ELF`) |
| `roppy.asm` | Assembly and disassembly (`assemble`, `disasm`) |
| `roppy.misc` | Packing utilities (`p32`, `p64`, `u32`, `u64`) |
| `roppy.libformatstr` | Format string exploitation tools |
| `roppy.rop` | ROP utilities (SROP frames) |
| `roppy.shellcode` | Pre-built shellcode templates |

## 🔧 Dependencies

- **[pyelftools](https://github.com/eliben/pyelftools)** - ELF file parsing
- **[keystone-engine](https://www.keystone-engine.org/)** - Multi-architecture assembler
- **[capstone](https://www.capstone-engine.org/)** - Disassembly framework
- **[requests](https://requests.readthedocs.io/)** - HTTP library

## 📖 Documentation

Full documentation is available on the [Wiki](https://github.com/D4mianWayne/roppy/wiki/)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎓 Examples

Check out the [examples](examples/) directory for complete exploitation scripts:

- **[Buffer Overflow](examples/bof/)** - Basic buffer overflow exploitation
- **[Format String](examples/fmt/)** - Format string vulnerability exploitation
- **[ret2libc](examples/ret2libc/)** - Return-to-libc attacks

## 🌟 Acknowledgments

This project was created to provide a lightweight, educational alternative for binary exploitation. Inspired by similar tools in the pwning community.

## ⚠️ Disclaimer

This tool is for educational and authorized security research purposes only. Users are responsible for complying with applicable laws and regulations.

---

**Made with ❤️ by [D4mianWayne](https://github.com/D4mianWayne)**