from subprocess import *
import tempfile
import os



class Asm(object):
    cmd = {
        'i386': {
            'as': ['as', '--32', '--msyntax=intel', '--mnaked-reg', '-o'],
            'objdump': ['objdump', '-M', 'intel', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'i386', '-M', 'intel,i386', '-D'],
        },
        'x86-64': {
            'as': ['as', '--64', '--msyntax=intel', '--mnaked-reg', '-o'],
            'objdump': ['objdump', '-M', 'intel', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'i386', '-M', 'intel,x86-64', '-D'],
        },
        'arm': {
            'as': ['as', '-o'],
            'objdump': ['objdump', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'arm', '-D'],
        },
        'thumb': {
            'as': ['as', '-mthumb', '-o'],
            'objdump': ['objdump', '-M', 'force-thumb', '-d'],
            'objdump_binary': ['objdump', '-b', 'binary', '-m', 'arm', '-M', 'force-thumb', '-D'],
        },
    }



    @classmethod
    def asm(cls, s, arch):
        if arch in cls.cmd:
            assembler = cls.cmd[arch]
        else:
            raise Exception("unsupported architecture: %r" % arch)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            p = Popen(cmd['as'] + [f.name], stdin=PIPE, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(s + b'\n')
            if stderr:
                return stderr
            p = Popen(cmd['objdump'] + ['-w', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            result = b''.join(stdout.splitlines(True)[7:])
            os.remove(f.name)
            return result


    @classmethod
    def disasm(cls, blob, arch):
        if arch in cls.cmd:
            cmd = cls.cmd[arch]
        else:
            raise Exception("Unsupported Architecture: %r" % arch)

        with tempfile.NamedTemporaryFile() as f:
            f.write(blob)
            f.flush()
            if arch in ('arm', 'thumb'):
                p = Popen(cmd['objdump_binary'] + ['-EB', '-w', f.name], stdout=PIPE)
            else:
                p = Popen(cmd['objdump_binary'] + ['-w', f.name], stdout=PIPE)
            stdout, stderr = p.communicate()
            result = b''.join(stdout.splitlines(True)[7:])
            return result
