import argparse

parser = argparse.ArgumentParser(
    description="Generate a template for exploit script"
)

parser.add_argument('--binary', type=str,metavar='binary', help="Binary file for analysiss")
parser.add_argument('--host', type=str, metavar='host', help="Host to connect")
parser.add_argument('--port', type=int,metavar='host', help="Host port to connect")


def template():
    args = parser.parse_args()
    template = """
    #!/usr/bin/python3
    # 
    from roppy import *
    
    context.binary = '{}'
    HOST, PORT = '{}', {}
    
    LOCAL = True
    
    if LOCAL:
        io = process(context.binary)
        elf = ELF(context.binary)
        libc = elf.libc
    else:
        io = remote(HOST, PORT)
        elf = ELF(context.binary)
    
    # ======================== #
    # Exploit code             #
    # ======================== #
     
    def exploit():
        return
    
    if __name__ == '__main__':
        exploit()
        """.format(args.binary, args.host, args.port)
    
    return template