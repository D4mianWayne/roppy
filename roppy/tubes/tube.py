# coding: utf-8
from ..misc import *
from abc import ABCMeta, abstractmethod
import threading
import time
from logging import getLogger

logger = getLogger(__name__)

class Tube(metaclass=ABCMeta):
    def __init__(self):
        self.buf = b''

    @abstractmethod
    def _settimeout(self, timeout):
        pass



    def recv(self, size, timeout):
        """Receive raw data with buffering

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        if size > len(self.bufsize):
            self.buf += self._recv(size, timeout)
        print(b"self.buf:        "+self.buf)

        data, self.buf = self.buf[:size], self.buf[size:]
        print("wtf")
        return data

    def recvonce(self, size, timeout):
        """Receive raw data with buffering

        Receive raw data of size `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        data = b''
        while len(data) < size:
            data += self.recv(size - len(data))

        if len(data) > size:
            self.unget(data[size:])
        return data[:size]


    def recvuntil(self, delim, size=4096, timeout=None):
        """Receive raw data until `delim` comes

        Args:
            size (int)   : The data size to receive at once
            delim (bytes): The delimiter bytes
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """

        if isinstance(delim, str):
            delim = str2bytes(delim)
        data = b''

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
            obj = self.recv(recv_size, timeout)
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

    def recvline(self, size=4096, timeout=None, drop=True):
        data = self.recvuntil(b"\n")
        if drop:
            data = data.strip(b"\n")
        return data

    @abstractmethod
    def send(self, data, timeout):
        pass

    def sendline(self, data, timeout=None):
        """Send a line

        Send a line of data.

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        if isinstance(data, str):
            data = str2bytes(data)
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
            data = str2bytes(data)
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
            data = str2bytes(data)
        recv_data = self.recvuntil(delim, timeout)
        self.sendline(data, timeout)
        return recv_data

    def interactive(self, timeout=None):
        """Interactive mode
        """
        log.info("Switching to Interactive mode.")
        go = threading.Event()

        def recv_thread():
            while not go.is_set():
                try:
                    cur = self.recv(timeout=0.05)
                    if cur:
                        print(cur.decode("latin"), end='')
                except EOFError:
                    log.info('Got EOF while reading in interactive')
                    break

        t = threading.Thread(target=recv_thread)
        t.daemon = True
        t.start()

        try:
            while not go.is_set():
                time.sleep(0.05)
                data = input("$ ")

                if data:
                    try:
                        self.sendline(data)
                    except EOFError:
                        go.set()
                        log.info('Got EOF while sending in interactive')
                else:
                    go.set()
        except KeyboardInterrupt:
            log.info('Interrupted')
            go.set()

        while t.is_alive():
            t.join(timeout=0.1)

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def shutdown(self, target):
        pass
