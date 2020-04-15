import argparse
import sys

config = {"version": "Beta"}

class Argument(object):
    def __init__(self, args=None):
        self.__args = None

        custom_arguments = True

        if not args:                                # If no arguments are provided
            args = sys.argv[1:]
            custom_arguments = False
        
        self.__parse(args, custom_arguments)
    
    def __parse(self, args, custom_arguments=True):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
        roppy - A toolkit to assist you in the process of exploiting a binary.
        It relies on Capstone disassembler and other GNU Binary Utils.
        
        ===============================================================
        
        Supported Binary Formats: 
        - ELF

        ===============================================================
        
        Supported Architectures:
        - x86-64
        - x86-32
        
        """,                                                                epilog="""examples
        
        roppy.py --file example --gadgets 
        roppy.py --file example --shellcode "Linux"
        roppy.py --file example --enumerate
        roppy.py --file example --pattern-create  200
        roppy.py --file example --pattern-offset aaaaaaaf 
        roppy.py --file example --checksec
        roppy.py --file example --scan <regex-pattern>
        roppy.py --file example --asm <input>
        roppy.py --file example --show-shellcode <ID>
        roppy.py --file example --objdump
         """)

        parser.add_argument("--gadgets", action="store_true", help="List all the gadgets from the binary.")
        parser.add_argument("-shellcode", metavar="<search term>", help="Search shellcode from shell-storm.org API.")
        parser.add_argument("--enumerate", metavar="", help="Enumerate the binary for all available gadgets and symbols.")
        parser.add_argument("--checksec", action="store_true", help="Check the security/protections on binary.")
        parser.add_argument("--file", metavar="<binary>", help="The binary file on which the operations will be performed.")
        parser.add_argument("--objdump", metavar="", help="Dump the symbols from file with IDA Notations")
        parser.add_argument("--pc", metavar="size", type=int, help="Generate a cyclic pattern")
        parser.add_argument("--scan", metavar="regex_expression", help="Scan for regex expression within the binary.")
        parser.add_argument("--asm", metavar="instructions", help="Assemble/Disassemble asm instructions.")
        parser.add_argument("--show-shellcode", metavar="<ID>", help="Scraps the shellcode with given ID found earlier with shellcode search.")
        parser.add_argument("--po", metavar="pattern", type=str, help="Find the offset of the pattern.")
        parser.add_argument("--version", action="store_true", help="Print the version of roppy.")
        parser.add_argument("--list",action="store_true", help="List gadgets available on the binary.")

        self.__args = parser.parse_args(args)

        if self.__args.version:
            self.__printVersion()
            sys.exit(0)
        
        elif not custom_arguments and not self.__args.file:
            print("[Error] Need a binary filename (--file <binary> --help)")
            sys.exit(-1)
        
    def __printVersion(self):
        print("""
        ====================================
        [+] Author: D4mianWayne
        [+] Name: roppy
        [+] Description: A ROP assistance toolkit based on GNU BinUtils.
        [+] Version: {}
        ====================================""".format(config['version']))


    def getArgs(self):
        return self.__args

