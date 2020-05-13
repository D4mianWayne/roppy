from abc import ABCMeta, abstractmethod
import threading
import time
import sys
from .buffer import Reservoir
from termcolor import colored
from ..log import *



class Tube(metaclass=ABCMeta):

    def __init__(self):

        self.buffer = Reservoir()

    @abstractmethod
    def _settimeout(self, timeout):
        pass

    @abstractmethod
    def recvonce(self, size, timeout):
        pass

    def recv(self, numb=4096, timeout=None):
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
        return self._recv(numb) 
    
    def _fillbuffer(self, timeout=None):
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
        #data = b''
        data = self.recv_raw(4096, timeout)

        if data:
            self.buffer.add(data)

        return data

    def _recv(self, numb=4096, timeout=None):
        """_recv(numb=4096, timeout=default) -> bytes
        Receives one chunk from the internal buffer or from the OS if the
        buffer is empty.
        """

        # No buffered data, could not put anything in the buffer
        # before timeout.
        if not self.buffer and not self._fillbuffer(timeout):
            return b''

        return self.buffer.get(numb)


    def recvall(self, size=4096, timeout=None):
        """Receive all data

        Receive all data through the socket.

        Args:
            size (int)   : Data size to receive at once
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        data = b''
        while True:
            part = self.recv(size)
            data += part
        return data

    def recvline(self, timeout=None, drop=True):
        """Receive a line

        Receive a line of raw data through the socket.

        Args:
            timeout (int): Timeout (in second)
            drop (bool)  : Whether or not to strip the newline

        Returns:
            bytes: The received data
        """
        data = b''
        c = None
        while c != b'\n':
            c = self.recvonce(1, timeout)
            if c is None:
                # Timeout
                break
            else:
                data += c
        if drop:
            return data.rstrip()
        else:
            return data

    def recvuntil(self, delim, timeout=None):
        """Receive raw data until `delim` comes

        Args:
            delim (bytes): The delimiter bytes
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        if isinstance(delim, str):
            delim = delim.encode("latin")
        data = b''
        length = len(delim)

        # Create the Boyer-Moore table
        bm_table = [length for i in range(0x100)]
        for (i, c) in enumerate(delim):
            bm_table[c] = length - i - 1

        # Receive data until the delimiter comes
        recv_size = length
        obj = None
        while True:
            # Receive
            obj = self.recvonce(recv_size, timeout)
            if obj is None:
                # Timeout
                break
            else:
                data += obj
            # Search
            i = -1
            j = length - 1
            while j >= 0:
                if data[i] != delim[j]: break
                i, j = i - 1, j - 1
            if j < 0:
                # Delimiter found
                break
            recv_size = max(bm_table[data[i]], length - j)
            i += recv_size
        return data

    def send(self, data, timeout=None):
        self.send_raw(data, timeout)

    def sendline(self, data, timeout=None):
        """Send a line

        Send a line of data.

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        if isinstance(data, str):
            data = data.encode("latin")
        self.send(data + b'\n', timeout)

    def sendafter(self, delim, data, timeout=None):
        """Send raw data after a deliminater

        Send raw data after `delim` is received.

        Args:
            delim (bytes): The deliminater
            data (bytes) : Data to send
            timeout (int): Timeout (in second)

        Returns:
            bytes: Received bytes before `delim` comes.
        """
        if isinstance(data, str):
            data = data.encode("latin")
        recv_data = self.recvuntil(delim, timeout)
        self.send(data, timeout)
        return recv_data

    def sendlineafter(self, delim, data, timeout=None):
        """Send raw data after a deliminater

        Send raw data with newline after `delim` is received.

        Args:
            delim (bytes): The deliminater
            data (bytes) : Data to send
            timeout (int): Timeout (in second)

        Returns:
            bytes: Received bytes before `delim` comes.
        """
        if isinstance(data, str):
            data = data.encode("latin")
        recv_data = self.recvuntil(delim, timeout)
        self.sendline(data, timeout)
        return recv_data
    
    @abstractmethod
    def recv_raw(self, numb):
        pass

    @abstractmethod
    def send_raw(self, data):
        pass

    def interactive(self, timeout=None):
        """
        Interactive mode to interact with the
        running process.
        """
        logger.info("Switching to Interactive mode")
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
                    logger.info('Got EOF while reading in interactive')
                    break

        t = threading.Thread(target=recv_thread)
        t.daemon = True
        t.start()

        try:
            while not go.is_set():
                print(colored("$ ", "cyan", attrs=['bold']), end='')
                data = sys.stdin.readline()
                if data:
                    try:
                        self.sendline(data)
                    except EOFError:
                        go.set()
                        logger.info('Got EOF while sending in interactive')
                else:
                    go.set()
        except KeyboardInterrupt:
            logger.info('Interrupted')
            go.set()

        while t.is_alive():
            t.join(timeout=0.1)

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def shutdown(self, target):
        pass
