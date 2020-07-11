import base64
import errno
import os
import re
import socket
import stat
import string

from roppylib.log import getLogger

log = getLogger(__name__)


def force_bytes(s):
    """force_bytes(s) -> bytes

    Ensures the given argument is of type bytes

    Example:

        >>> force_bytes(b'abc')
        b'abc'
        >>> force_bytes('abc')
        b'abc'
        >>> force_bytes(1)
        Traceback (most recent call last):
            ...
        TypeError: Expecting a value of type bytes or str, got 1
    """
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode('utf8')
    else:
        raise TypeError('Expecting a value of type bytes or str, got %r' % s)




def size(n, abbriv='B', si=False):
    """size(n, abbriv='B', si=False) -> str

    Convert the length of a bytestream to human readable form.

    Arguments:
        n(int,str): The length to convert to human readable form
        abbriv(str):

    Example:
        >>> size(451)
        '451B'
        >>> size(1000)
        '1000B'
        >>> size(1024)
        '1.00KB'
        >>> size(1024, si=True)
        '1.02KB'
        >>> [size(1024 ** n) for n in range(7)]
        ['1B', '1.00KB', '1.00MB', '1.00GB', '1.00TB', '1.00PB', '1024.00PB']
    """
    if isinstance(n, (bytes, str)):
        n = len(n)

    base = 1000.0 if si else 1024.0
    if n < base:
        return '%d%s' % (n, abbriv)

    for suffix in ('K', 'M', 'G', 'T'):
        n /= base
        if n < base:
            return '%.02f%s%s' % (n, suffix, abbriv)

    return '%.02fP%s' % (n / base, abbriv)

KB = 1024
MB = 1024 * KB
GB = 1024 * MB

KiB = 1000
MiB = 1000 * KB
GiB = 1000 * MB


def read(path, count=-1, skip=0, mode='r'):
    """read(path, count=-1, skip=0, mode='r') -> bytes or str

    Open file, return content.

    Examples:
        >>> read('pwnlib/util/misc.py').split('\\n')[0]
        'import base64'
    """
    path = os.path.expanduser(os.path.expandvars(path))
    with open(path, mode) as fd:
        if skip:
            fd.seek(skip)
        return fd.read(count)




def which(name, all=False):
    """which(name, flags=os.X_OK, all=False) -> str or str set

    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.

    If `all` is :const:`True` the set of all found locations is returned, else
    the first occurence or :const:`None` is returned.

    Arguments:
        name (str): The file to search for.
        all (bool):  Whether to return all locations where `name` was found.

    Returns:
        If `all` is :const:`True` the set of all locations where `name` was found,
        else the first location or :const:`None` if not found.

    Example:
        >>> which('sh')
        '/bin/sh'
    """
    # If name is a path, do not attempt to resolve it.
    if os.path.sep in name:
        return name

    isroot = os.getuid() == 0
    out = set()
    try:
        path = os.environ['PATH']
    except KeyError:
        log.exception('Environment variable $PATH is not set')
    for p in path.split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, os.X_OK):
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            # work around this issue: https://bugs.python.org/issue9311
            if isroot and not \
                    st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                continue
            if all:
                out.add(p)
            else:
                return p
    if all:
        return out
    else:
        return None



def parse_ldd_output(output):
    """Parses the output from a run of 'ldd' on a binary.
    Returns a dictionary of {path: address} for
    each library required by the specified binary.

    Arguments:
        output(bytes, str): The output to parse

    Example:
        >>> sorted(parse_ldd_output('''
        ...     linux-vdso.so.1 =>  (0x00007fffbf5fe000)
        ...     libtinfo.so.5 => /lib/x86_64-linux-gnu/libtinfo.so.5 (0x00007fe28117f000)
        ...     libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe280f7b000)
        ...     libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe280bb4000)
        ...     /lib64/ld-linux-x86-64.so.2 (0x00007fe2813dd000)
        ... ''').keys())
        ['/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libdl.so.2', '/lib/x86_64-linux-gnu/libtinfo.so.5', '/lib64/ld-linux-x86-64.so.2']
    """
    if isinstance(output, bytes):
        output = output.decode('utf8', 'surrogateescape')

    expr_linux = re.compile(r'\s(?P<lib>\S?/\S+)\s+\((?P<addr>0x.+)\)')
    expr_openbsd = re.compile(r'^\s+(?P<addr>[0-9a-f]+)\s+[0-9a-f]+\s+\S+\s+[01]\s+[0-9]+\s+[0-9]+\s+(?P<lib>\S+)$')
    libs = {}

    for s in output.split('\n'):
        match = expr_linux.search(s) or expr_openbsd.search(s)
        if not match:
            continue
        lib, addr = match.group('lib'), match.group('addr')
        libs[lib] = int(addr, 16)

    return libs


def mkdir_p(path):
    """Emulates the behavior of ``mkdir -p``."""
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

