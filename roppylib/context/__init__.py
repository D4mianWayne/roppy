#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Implements context management so that nested/scoped contexts and threaded
contexts work properly and as expected.
"""
import collections
import functools
import logging
import os
import platform
import socks
import socket
import string
import sys
import threading
import time

from ..timeout import Timeout

_original_socket = socket.socket


class _devnull:
    name = None
    def write(self, *a, **kw): pass
    def read(self, *a, **kw): return ''
    def flush(self, *a, **kw): pass
    def close(self, *a, **kw): pass


class DefaultDict(dict):

    def __init__(self, default=None):
        super(DefaultDict, self).__init__()
        if default is None:
            default = {}

        self.default = default

    def __missing__(self, key):
        return self.default[key]


class DictStack:

    def __init__(self, default):
        self._current = DefaultDict(default)
        self.__stack = []

    def push(self):
        self.__stack.append(self._current.copy())

    def pop(self):
        self._current.clear()
        self._current.update(self.__stack.pop())

    def copy(self):
        return self._current.copy()

    # Pass-through container emulation routines
    def __len__(self):
        return self._current.__len__()

    def __delitem__(self, k):
        return self._current.__delitem__(k)

    def __getitem__(self, k):
        return self._current.__getitem__(k)

    def __setitem__(self, k, v):
        return self._current.__setitem__(k, v)

    def __contains__(self, k):
        return self._current.__contains__(k)

    def __iter__(self):
        return self._current.__iter__()

    def __repr__(self):
        return self._current.__repr__()

    def __eq__(self, other):
        return self._current.__eq__(other)

    # Required for keyword expansion operator ** to work
    def keys(self):
        return self._current.keys()

    def values(self):
        return self._current.values()

    def items(self):
        return self._current.items()


class _TlsDictStack(threading.local, DictStack):
    """
    Per-thread implementation of :class:`DictStack`.

    Examples:

        >>> t = pwnlib.context._TlsDictStack({})
        >>> t['key'] = 'value'
        >>> print(t)
        {'key': 'value'}
        >>> def p(): print(t)
        >>> thread = threading.Thread(target=p)
        >>> _ = (thread.start(), thread.join())
        {}
    """
    pass


def _validator(validator):
    """
    Validator that tis tightly coupled to the implementation
    of the classes here.

    This expects that the object has a ._tls property which
    is of type DictStack.
    """

    name = validator.__name__
    doc = validator.__doc__

    def fget(self):
        return self._tls[name]

    def fset(self, val):
        self._tls[name] = validator(self, val)

    def fdel(self):
        self._tls._current.pop(name, None)

    return property(fget, fset, fdel, doc)



def _longest(d):
    """
    Returns an OrderedDict with the contents of the input dictionary ``d``
    sorted by the length of the keys, in descending order.

    This is useful for performing substring matching via ``str.startswith``,
    as it ensures the most complete match will be found.

    Examples:

        >>> data = {'a': 1, 'bb': 2, 'ccc': 3}
        >>> _longest(data) == data
        True
        >>> for i in _longest(data): print(i)
        ccc
        bb
        a
    """
    return collections.OrderedDict((k, d[k]) for k in sorted(d, key=len, reverse=True))


class TlsProperty:

    def __get__(self, obj, objtype=None):
        return obj._tls


class ContextType:
    r"""
    Class for specifying information about the target machine.
    Intended for use as a pseudo-singleton through the global
    variable ``pwnlib.context.context``, available via
    ``from pwn import *`` as ``context``.

    The context is usually specified at the top of the Python file for clarity. ::

        #!/usr/bin/env python3
        context.update(arch='i386', os='linux')

    Currently supported properties and their defaults are listed below.
    The defaults are inherited from :data:`pwnlib.context.ContextType.defaults`.

    Additionally, the context is thread-aware when using
    :class:`pwnlib.context.Thread` instead of :class:`threading.Thread`
    (all internal ``pwntools`` threads use the former).

    The context is also scope-aware by using the ``with`` keyword.

    Examples:

        >>> context.clear()
        >>> context.update(os='linux') # doctest: +ELLIPSIS
        >>> context.os == 'linux'
        True
        >>> context.arch = 'arm'
        >>> vars(context) == {'arch': 'arm', 'bits': 32, 'endian': 'little', 'os': 'linux'}
        True
        >>> context.endian
        'little'
        >>> context.bits
        32
        >>> def nop():
        ...   print(enhex(pwnlib.asm.asm('nop')))
        >>> nop()
        00f020e3
        >>> with context.local(arch = 'i386'):
        ...   nop()
        90
        >>> from pwnlib.context import Thread as PwnThread
        >>> from threading import Thread as NormalThread
        >>> with context.local(arch = 'mips'):
        ...     pwnthread = PwnThread(target=nop)
        ...     thread = NormalThread(target=nop)
        >>> # Normal thread uses the default value for arch, 'i386'
        >>> _ = (thread.start(), thread.join())
        90
        >>> # Pwnthread uses the correct context from creation-time
        >>> _ = (pwnthread.start(), pwnthread.join())
        00000000
        >>> nop()
        00f020e3
    """

    #
    # Use of 'slots' is a heavy-handed way to prevent accidents
    # like 'context.architecture=' instead of 'context.arch='.
    #
    # Setting any properties on a ContextType object will throw an
    # exception.
    #
    __slots__ = '_tls',

    #: Default values for :class:`pwnlib.context.ContextType`
    defaults = {
        'arch': 'amd64',
        'aslr': True,
        'binary': None,
        'bits': 32,
        'endian': 'little',
        'kernel': None,
        'log_level': logging.INFO,
        'newline': '\n',
        'os': 'linux',
        'timeout': Timeout.maximum,
    }

    #: Valid values for :meth:`pwnlib.context.ContextType.os`
    oses = sorted(('linux', 'freebsd', 'windows', 'cgc', 'android'))

    big_32 = {'endian': 'big', 'bits': 32}
    big_64 = {'endian': 'big', 'bits': 64}
    little_8 = {'endian': 'little', 'bits': 8}
    little_16 = {'endian': 'little', 'bits': 16}
    little_32 = {'endian': 'little', 'bits': 32}
    little_64 = {'endian': 'little', 'bits': 64}

    #: Keys are valid values for :meth:`pwnlib.context.ContextType.arch`.
    #
    #: Values are defaults which are set when
    #: :attr:`pwnlib.context.ContextType.arch` is set
    architectures = _longest({
        'amd64': little_64,
        'i386': little_32,
    })

    #: Valid values for :attr:`endian`
    endiannesses = _longest({
        'be': 'big',
        'eb': 'big',
        'big': 'big',
        'le': 'little',
        'el': 'little',
        'little': 'little'
    })

    #: Valid string values for :attr:`signed`
    signednesses = {
        'unsigned': False,
        'no': False,
        'yes': True,
        'signed': True
    }

    valid_signed = sorted(signednesses)

    def __init__(self, **kwargs):
        """
        Initialize the ContextType structure.

        All keyword arguments are passed to :func:`update`.
        """
        self._tls = _TlsDictStack(DefaultDict(ContextType.defaults))
        self.update(**kwargs)

    def copy(self):
        """copy() -> dict
        Returns a copy of the current context as a dictionary.

        Examples:

            >>> context.clear()
            >>> context.os = 'linux'
            >>> vars(context) == {'os': 'linux'}
            True
        """
        return self._tls.copy()

    @property
    def __dict__(self):
        return self.copy()

    def update(self, *args, **kwargs):
        """
        Convenience function, which is shorthand for setting multiple
        variables at once.

        It is a simple shorthand such that::

            context.update(os='linux', arch='arm', ...)

        is equivalent to::

            context.os = 'linux'
            context.arch = 'arm'
            ...

        The following syntax is also valid::

            context.update({'os': 'linux', 'arch': 'arm'})

        Arguments:
          kwargs: Variables to be assigned in the environment.

        Examples:

            >>> context.clear()
            >>> context.update(arch='i386', os='linux')
            >>> context.arch, context.os
            ('i386', 'linux')
        """
        for arg in args:
            self.update(**arg)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        v = sorted("%s = %r" % (k, v) for k, v in self._tls._current.items())
        return '%s(%s)' % (self.__class__.__name__, ', '.join(v))

    def local(self, **kwargs):

        class LocalContext:

            def __enter__(a):
                self._tls.push()
                self.update(**{k: v for k, v in kwargs.items() if v is not None})
                return self

            def __exit__(a, *b, **c):
                self._tls.pop()

        return LocalContext()

    @property
    def silent(self):

        return self.local(log_level='error')

    def clear(self, *args, **kwargs):

        self._tls._current.clear()

        if args or kwargs:
            self.update(*args, **kwargs)

    @property
    def native(self):
        arch = context.arch
        with context.local(arch=platform.machine()):
            platform_arch = context.arch

            if arch in ('i386', 'amd64') and platform_arch in ('i386', 'amd64'):
                return True

            return arch == platform_arch

    @_validator
    def arch(self, arch):

        # Lowercase
        arch = arch.lower()

        # Attempt to perform convenience and legacy compatibility transformations.
        # We have to make sure that x86_64 appears before x86 for this to work correctly.
        transform = [('x86_64', 'amd64'), ('x86', 'i386')]
        for k, v in transform:
            if arch.startswith(k):
                arch = arch.replace(k, v, 1)

        try:
            defaults = ContextType.architectures[arch]
        except KeyError:
            raise AttributeError('AttributeError: arch must be one of %r' %
                                 sorted(ContextType.architectures))

        for k, v in ContextType.architectures[arch].items():
            if k not in self._tls:
                self._tls[k] = v

        return arch

    @_validator
    def aslr(self, aslr):
        """
        ASLR settings for new processes.

        If ``False``, attempt to disable ASLR in all processes which are
        created via ``personality`` (``setarch -R``) and ``setrlimit``
        (``ulimit -s unlimited``).

        The ``setarch`` changes are lost if a ``setuid`` binary is executed.
        """
        return bool(aslr)

    @_validator
    def kernel(self, arch):

        with context.local(arch=arch):
            return context.arch

    @_validator
    def bits(self, bits):
  
        bits = int(bits)

        if bits <= 0:
            raise AttributeError("bits must be > 0 (%r)" % bits)

        return bits

    @_validator
    def binary(self, binary):
       # Cyclic imports... sorry Idolf.
        from roppylib.loaders.elf import ELF

        if not isinstance(binary, ELF):
            binary = ELF(binary)

        self.arch = binary.arch
        self.bits = binary.bits
        self.endian = binary.endian

        return binary

    @property
    def bytes(self):
        """
        Target machine word size, in bytes (i.e. the size of general purpose registers).

        This is a convenience wrapper around ``bits / 8``.

        Examples:

            >>> context.bytes = 1
            >>> context.bits == 8
            True
            >>> context.bytes = 0 #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            AttributeError: bits must be > 0 (0)
        """
        return self.bits // 8

    @bytes.setter
    def bytes(self, value):
        self.bits = value * 8



    @_validator
    def log_level(self, value):

        # If it can be converted into an int, success
        try:
            return int(value)
        except ValueError:
            pass

        # If it is defined in the logging module, success
        try:
            return getattr(logging, value.upper())
        except AttributeError:
            pass

        # Otherwise, fail
        permitted = sorted(v.lower() for v in logging._levelToName.values())
        raise AttributeError('log_level must be an integer or one of %r' % permitted)

    @property
    def mask(self):
        return (1 << self.bits) - 1

    @_validator
    def os(self, os):
  
        os = os.lower()

        if os not in ContextType.oses:
            raise AttributeError("os must be one of %r" % ContextType.oses)

        return os


    @_validator
    def timeout(self, value=Timeout.default):

        return Timeout(value).timeout

    #*************************************************************************
    #                               ALIASES
    #*************************************************************************
    #
    # These fields are aliases for fields defined above, either for
    # convenience or compatibility.
    #
    #*************************************************************************




    Thread = threading.Thread


#: Global ``context`` object, used to store commonly-used pwntools settings.
#: In most cases, the context is used to infer default variables values.
#: For example, :meth:`pwnlib.asm.asm` can take an ``os`` parameter as a
#: keyword argument.  If it is not supplied, the ``os`` specified by
#: ``context`` is used instead.
#: Consider it a shorthand to passing ``os=`` and ``arch=`` to every single
#: function call.
context = ContextType()


def local(function):
    """
    Wraps the specied function on a context.local() block, using kwargs.

    Example:

        >>> @local_context
        ... def printArch():
        ...     print(context.arch)
        >>> printArch()
        i386
        >>> printArch(arch='arm')
        arm
    """
    @functools.wraps(function)
    def setter(*args, **kwargs):
        # Fast path to skip adding a Context frame
        if not kwargs:
            return function(*args)

        context_args = {k: v for k, v in kwargs.items()
                        if isinstance(getattr(ContextType, k, None), property)}

        for k in context_args.keys():
            del kwargs[k]

        with context.local(**context_args):
            return function(*args, **kwargs)
    return setter
