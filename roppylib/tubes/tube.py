# -*- coding: utf-8 -*-
import logging
import re
import string
import subprocess
import sys
import threading
import time

from roppylib import atexit
from roppylib import term
from roppylib.context import context
from roppylib.log import Logger
from roppylib.timeout import Timeout
from roppylib.util.misc import hexdump
from roppylib.util.misc import tobytes
from roppylib.tubes.buffer import Buffer


class tube(Timeout, Logger):
    """
    Container of all the tube functions common to sockets, TTYs and SSH connetions.
    """

    default = Timeout.default
    forever = Timeout.forever

    #: Delimiter to use for :meth:`sendline`, :meth:`recvline`,
    #: and related functions.
    newline = b'\n'

    def __init__(self, timeout=default, level=None):
        Timeout.__init__(self, timeout)
        Logger.__init__(self, None)

        if level is not None:
            self.setLevel(level)

        self.buffer = Buffer()
        atexit.register(self.close)

    # Functions based on functions from subclasses
    def recv(self, numb=4096, timeout=default):
        r"""recv(numb=4096, timeout=default) -> bytes

        Receives up to `numb` bytes of data from the tube, and returns
        as soon as any quantity of data is available.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty bytes (``b''``) is returned.

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A string containing bytes received from the socket,
            or ``b''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> # Fake a data source
            >>> t.recv_raw = lambda n: b'Hello, world'
            >>> t.recv() == b'Hello, world'
            True
            >>> t.unrecv(b'Woohoo')
            >>> t.recv() == b'Woohoo'
            True
            >>> with context.local(log_level='debug'):
            ...    _ = t.recv() # doctest: +ELLIPSIS
            [...] Received 0xc bytes:
                b'Hello, world'
        """
        return self._recv(numb, timeout) or b''

    def unrecv(self, data):
        """unrecv(data)

        Puts the specified data back at the beginning of the receive
        buffer.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'hello'
            >>> t.recv()
            b'hello'
            >>> t.recv()
            b'hello'
            >>> t.unrecv(b'world')
            >>> t.recv()
            b'world'
            >>> t.recv()
            b'hello'
        """
        assert isinstance(data, bytes)
        self.buffer.unget(data)

    def _fillbuffer(self, timeout=default):
        """_fillbuffer(timeout=default) -> bytes

        Fills the internal buffer from the pipe, by calling
        :meth:`recv_raw` exactly once.

        Returns:
            The bytes of data received, or ``b''`` if no data was received.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'abc'
            >>> len(t.buffer)
            0
            >>> t._fillbuffer()
            b'abc'
            >>> len(t.buffer)
            3
        """
        data = b''

        with self.local(timeout):
            data = self.recv_raw(4096)

        if data and self.isEnabledFor(logging.DEBUG):
            self.debug('Received %#x bytes:' % len(data))

            if len(set(data)) == 1 and len(data) > 1:
                self.indented('%r * %#x' % (data[:1], len(data)))
            elif all(chr(c) in string.printable for c in data):
                for line in data.splitlines(True):
                    self.indented(repr(line), level=logging.DEBUG)
            else:
                self.indented(hexdump(data), level=logging.DEBUG)

        if data:
            self.buffer.add(data)

        return data

    def _recv(self, numb=4096, timeout=default):
        """_recv(numb=4096, timeout=default) -> bytes

        Receives one chunk from the internal buffer or from the OS if the
        buffer is empty.
        """
        # No buffered data, could not put anything in the buffer
        # before timeout.
        if not self.buffer and not self._fillbuffer(timeout):
            return b''

        return self.buffer.get(numb)

    def recvpred(self, pred, timeout=default):
        """recvpred(pred, timeout=default) -> bytes

        Receives one byte at a time from the tube, until ``pred(bytes)``
        evaluates to True.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty bytes (``b''``) is returned.

        Arguments:
            pred(callable): Function to call, with the currently-accumulated data.
            timeout(int): Timeout for the operation

        Raises:
            exceptions.EOFError: The connection is closed

        Returns:
            A string containing bytes received from the socket,
            or ``b''`` if a timeout occurred while waiting.
        """
        data = b''

        with self.countdown(timeout):
            while not pred(data):
                try:
                    res = self.recv(1)
                except Exception:
                    self.unrecv(data)
                    return b''

                if res:
                    data += res
                else:
                    self.unrecv(data)
                    return b''

        return data

    def recvn(self, numb, timeout=default):
        """recvn(numb, timeout=default) -> bytes

        Receives exactly `n` bytes.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty bytes (``b''``) is returned.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``b''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> data = b'hello world'
            >>> t.recv_raw = lambda n: data
            >>> t.recvn(len(data)) == data
            True
            >>> t.recvn(len(data)+1) == data + data[0:1]
            True
            >>> t.recv_raw = lambda n: None
            >>> # The remaining data is buffered
            >>> t.recv() == data[1:]
            True
            >>> t.recv_raw = lambda *a: time.sleep(0.01) or b'a'
            >>> t.recvn(10, timeout=0.05)
            b''
            >>> t.recvn(10, timeout=0.06) # doctest: +ELLIPSIS
            b'aaaaaaaaaa'
        """
        # Keep track of how much data has been received
        # It will be pasted together at the end if a
        # timeout does not occur, or put into the tube buffer.
        with self.countdown(timeout):
            while (self.countdown_active() and
                   len(self.buffer) < numb and
                   self._fillbuffer(self.timeout)):
                pass

        if len(self.buffer) < numb:
            return b''

        return self.buffer.get(numb)

    def recvuntil(self, delims, drop=False, timeout=default):
        """recvuntil(delims, timeout=default) -> bytes

        Receive data until one of `delims` is encountered.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty bytes (``b''``) is returned.

        arguments:
            delims(bytes,str,tuple): String of delimiters characters, or list of delimiter strings.
            drop(bool): Drop the ending.  If ``True`` it is removed from the end of the return value.

        Raises:
            exceptions.EOFError: The connection closed before the request could be satisfied

        Returns:
            A string containing bytes received from the socket,
            or ``b''`` if a timeout occurred while waiting.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello World!"
            >>> t.recvuntil(' ')
            b'Hello '
            >>> _ = t.clean(0)
            >>> # Matches on 'o' in 'Hello'
            >>> t.recvuntil(tuple(' Wor'))
            b'Hello'
            >>> _ = t.clean(0)
            >>> # Matches expressly full string
            >>> t.recvuntil(b' Wor')
            b'Hello Wor'
            >>> _ = t.clean(0)
            >>> # Matches on full string, drops match
            >>> t.recvuntil(' Wor', drop=True)
            b'Hello'

            >>> # Try with regex special characters
            >>> t = tube()
            >>> t.recv_raw = lambda n: b"Hello|World"
            >>> t.recvuntil('|', drop=True)
            b'Hello'
        """
        # Convert bytes/string into singleton tupple
        if isinstance(delims, (bytes, str)):
            delims = (delims,)

        # Make sure all items are bytes
        delims = list(map(tobytes, delims))

        # Longest delimiter for tracking purposes
        longest = max(map(len, delims))

        # Cumulative data to search
        data = []
        top = b''

        with self.countdown(timeout):
            while self.countdown_active():
                try:
                    res = self.recv(timeout=self.timeout)
                except Exception:
                    self.unrecv(b''.join(data) + top)
                    raise

                if not res:
                    self.unrecv(b''.join(data) + top)
                    return b''

                top += res
                start = len(top)
                for d in delims:
                    j = top.find(d)
                    if start > j > -1:
                        start = j
                        end = j + len(d)

                if start < len(top):
                    self.unrecv(top[end:])
                    if drop:
                        top = top[:start]
                    else:
                        top = top[:end]
                    return b''.join(data) + top

                if len(top) > longest:
                    i = -longest - 1
                    data.append(top[:i])
                    top = top[i:]

        return b''


    def recvline(self, keepends=True, timeout=default):
        r"""recvline(keepends=True) -> bytes

        Receive a single line from the tube.

        A "line" is any sequence of bytes terminated by the byte sequence
        set in :attr:`newline`, which defaults to ``b'\n'``.

        If the request is not satisfied before ``timeout`` seconds pass,
        all data is buffered and an empty bytes (``b''``) is returned.

        Arguments:
            keepends(bool): Keep the line ending (``True``).
            timeout(int): Timeout

        Return:
            All bytes received over the tube until the first
            newline ``b'\n'`` is received.  Optionally retains
            the ending.

        Examples:

            >>> t = tube()
            >>> t.recv_raw = lambda n: b'Foo\nBar\r\nBaz\n'
            >>> t.recvline()
            b'Foo\n'
            >>> t.recvline()
            b'Bar\r\n'
            >>> t.recvline(keepends=False)
            b'Baz'
            >>> t.newline = b'\r\n'
            >>> t.recvline(keepends=False)
            b'Foo\nBar'
        """
        return self.recvuntil(self.newline, drop=not keepends, timeout=timeout)


    def recvall(self, timeout=Timeout.forever):
        """recvall() -> bytes

        Receives data until EOF is reached.
        """
        with self.waitfor('Recieving all data') as h:
            l = len(self.buffer)
            with self.local(timeout):
                try:
                    while True:
                        l = str(len(self.buffer))
                        h.status(l)
                        if not self._fillbuffer():
                            break
                except EOFError:
                    pass
            h.success("Done (%s)" % l)
        self.close()

        return self.buffer.get()

    def send(self, data):
        """send(data)

        Sends data.

        If log level ``DEBUG`` is enabled, also prints out the data
        received.

        If it is not possible to send anymore because of a closed
        connection, it raises ``exceptions.EOFError``

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.send('hello')
            b'hello'
        """
        data = tobytes(data)

        if self.isEnabledFor(logging.DEBUG):
            self.debug('Sent %#x bytes:' % len(data))
            if len(set(data)) == 1:
                self.indented('%r * %#x' % (data[:1], len(data)))
            elif all(chr(c) in string.printable for c in data):
                for line in data.splitlines(True):
                    self.indented(repr(line), level=logging.DEBUG)
            else:
                self.indented(hexdump(data), level=logging.DEBUG)

        self.send_raw(data)

    def sendline(self, line=''):
        r"""sendline(data)

        Shorthand for ``t.send(data + t.newline)``.

        Examples:

            >>> def p(x): print(repr(x))
            >>> t = tube()
            >>> t.send_raw = p
            >>> t.sendline('hello')
            b'hello\n'
            >>> t.newline = b'\r\n'
            >>> t.sendline('hello')
            b'hello\r\n'
        """
        self.send(tobytes(line) + self.newline)

    def sendlines(self, lines=[]):
        for line in lines:
            self.sendline(line)

    def sendafter(self, delim, data, timeout=default):
        """sendafter(delim, data, timeout=default) -> bytes

        A combination of ``recvuntil(delim, timeout)`` and ``send(data)``.
        """
        res = self.recvuntil(delim, timeout)
        self.send(data)
        return res

    def sendlineafter(self, delim, data, timeout=default):
        """sendlineafter(delim, data, timeout=default) -> bytes

        A combination of ``recvuntil(delim, timeout)`` and ``sendline(data)``.
        """
        res = self.recvuntil(delim, timeout)
        self.sendline(data)
        return res

    def interactive(self, prompt=term.text.bold_cyan('$') + ' '):

        self.info('Switching to interactive mode')

        go = threading.Event()

        def recv_thread():
            while not go.is_set():
                try:
                    cur = self.recv(timeout=0.05)
                    if cur:
                        cur = cur.replace(b'\r\n', b'\n')
                        sys.stdout.buffer.write(cur)
                        sys.stdout.flush()
                except EOFError:
                    self.info('Got EOF while reading in interactive')
                    break

        t = threading.Thread(target=recv_thread)
        t.daemon = True
        t.start()

        try:
            while not go.is_set():
                if term.term_mode:
                    data = term.readline.readline(prompt=prompt, float=True)
                else:
                    data = sys.stdin.readline()

                if data:
                    try:
                        self.send(data)
                    except EOFError:
                        go.set()
                        self.info('Got EOF while sending in interactive')
                else:
                    go.set()
        except KeyboardInterrupt:
            self.info('Interrupted')
            go.set()

        while t.is_alive():
            t.join(timeout=0.1)


    def wait_for_close(self):
        """Waits until the tube is closed."""

        while self.connected():
            time.sleep(0.05)

    wait = wait_for_close

    def can_recv(self, timeout=0):
        """can_recv(timeout=0) -> bool

        Returns True, if there is data available within `timeout` seconds.

        Examples:

            >>> import time
            >>> t = tube()
            >>> t.can_recv_raw = lambda n: False
            >>> t.can_recv()
            False
            >>> _ = t.unrecv(b'data')
            >>> t.can_recv()
            True
            >>> _ = t.recv()
            >>> t.can_recv()
            False
        """
        return bool(self.buffer or self.can_recv_raw(timeout))

    def settimeout(self, timeout):
        """settimeout(timeout)

        Set the timeout for receiving operations. If the string "default"
        is given, then :data:`context.timeout` will be used. If None is given,
        then there will be no timeout.

        Examples:

            >>> t = tube()
            >>> t.settimeout_raw = lambda t: None
            >>> t.settimeout(3)
            >>> t.timeout == 3
            True
        """
        self.timeout = timeout

    shutdown_directions = {
        'in': 'recv',
        'read': 'recv',
        'recv': 'recv',
        'out': 'send',
        'write': 'send',
        'send': 'send',
    }

    connected_directions = shutdown_directions.copy()
    connected_directions['any'] = 'any'

    def shutdown(self, direction="send"):
        """shutdown(direction="send")

        Closes the tube for futher reading or writing depending on `direction`.

        Arguments:
          direction(str): Which direction to close; "in", "read" or "recv"
            closes the tube in the ingoing direction, "out", "write" or "send"
            closes it in the outgoing direction.

        Returns:
          :const:`None`

        Examples:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.shutdown_raw = p
            >>> _ = [t.shutdown(x) for x in ('in', 'read', 'recv', 'out', 'write', 'send')]
            recv
            recv
            recv
            send
            send
            send
            >>> t.shutdown('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['in', 'out', 'read', 'recv', 'send', 'write']"
        """
        try:
            direction = self.shutdown_directions[direction]
        except KeyError:
            raise KeyError('direction must be in %r' % sorted(self.shutdown_directions))
        else:
            self.shutdown_raw(self.shutdown_directions[direction])

    def connected(self, direction='any'):
        """connected(direction='any') -> bool

        Returns True if the tube is connected in the specified direction.

        Arguments:
          direction(str): Can be the string 'any', 'in', 'read', 'recv',
                          'out', 'write', 'send'.

        Doctest:

            >>> def p(x): print(x)
            >>> t = tube()
            >>> t.connected_raw = p
            >>> _ = [t.connected(x) for x in ('any', 'in', 'read', 'recv', 'out', 'write', 'send')]
            any
            recv
            recv
            recv
            send
            send
            send
            >>> t.connected('bad_value') #doctest: +ELLIPSIS
            Traceback (most recent call last):
            ...
            KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
        """
        try:
            direction = self.connected_directions[direction]
        except KeyError:
            raise KeyError('direction must be in %r' % sorted(self.connected_directions))
        else:
            return self.connected_raw(direction)

    def __enter__(self):
        """Permit use of 'with' to control scoping and closing sessions.

        Examples:

            >>> t = tube()
            >>> t.close = lambda: print("Closed!")
            >>> with t: pass
            Closed!
        """
        return self

    def __exit__(self, type, value, traceback):
        """Handles closing for 'with' statement

        See :meth:`__enter__`
        """
        self.close()

    # The minimal interface to be implemented by a child
    def recv_raw(self, numb):
        """recv_raw(numb) -> bytes

        Should not be called directly. Receives data without using the buffer
        on the object.

        Unless there is a timeout or closed connection, this should always
        return data. In case of a timeout, it should return None, in case
        of a closed connection it should raise an ``exceptions.EOFError``.
        """
        raise NotImplementedError()

    def send_raw(self, data):
        """send_raw(data)

        Should not be called directly. Sends data to the tube.

        Should return ``exceptions.EOFError``, if it is unable to send any
        more, because of a close tube.
        """
        raise NotImplementedError()

    def settimeout_raw(self, timeout):
        """settimeout_raw(timeout)

        Should not be called directly. Sets the timeout for
        the tube.
        """
        raise NotImplementedError()

    def timeout_change(self):
        """
        Informs the raw layer of the tube that the timeout has changed.

        Should not be called directly.

        Inherited from :class:`Timeout`.
        """
        try:
            self.settimeout_raw(self.timeout)
        except NotImplementedError:
            pass

    def can_recv_raw(self, timeout):
        """can_recv_raw(timeout) -> bool

        Should not be called directly. Returns True, if
        there is data available within the timeout, but
        ignores the buffer on the object.
        """
        raise NotImplementedError()

    def connected_raw(self, direction):
        """connected(direction='any') -> bool

        Should not be called directly.  Returns True iff the
        tube is connected in the given direction.
        """
        raise NotImplementedError()

    def close(self):
        """close()

        Closes the tube.
        """
        pass
        # Ideally we could:
        # raise NotImplementedError()
        # But this causes issues with the unit tests.

    def fileno(self):
        """fileno() -> int

        Returns the file number used for reading.
        """
        raise NotImplementedError()

    def shutdown_raw(self, direction):
        """shutdown_raw(direction)

        Should not be called directly.  Closes the tube for further reading or
        writing.
        """
        raise NotImplementedError()

    #: Alias for :meth:`recv`
    def read(self, *a, **kw): return self.recv(*a, **kw)

    #: Alias for :meth:`recvpred`
    def readpred(self, *a, **kw): return self.recvpred(*a, **kw)

    #: Alias for :meth:`recvn`
    def readn(self, *a, **kw): return self.recvn(*a, **kw)

    #: Alias for :meth:`recvuntil`
    def readuntil(self, *a, **kw): return self.recvuntil(*a, **kw)

    #: Alias for :meth:`recvline`
    def readline(self, *a, **kw): return self.recvline(*a, **kw)

    def interact(self, *a, **kw): return self.interactive(*a, *kw)

    #: Alias for :meth:`recvall`
    def readall(self, *a, **kw): return self.recvall(*a, **kw)

    #: Alias for :meth:`send`
    def write(self, *a, **kw): return self.send(*a, **kw)

    #: Alias for :meth:`sendline`
    def writeline(self, *a, **kw): return self.sendline(*a, **kw)

    #: Alias for :meth:`sendafter`
    def writeafter(self, *a, **kw): return self.sendafter(*a, **kw)

    #: Alias for :meth:`sendlineafter`
    def writelineafter(self, *a, **kw): return self.sendlineafter(*a, **kw)
