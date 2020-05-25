# coding: utf-8
from roppy.misc.utils import *
from roppy.tubes.tube import *
from roppy.log import log
import socket


class remote(Tube):
    """
    `roppy.tubes.remote` allows you to interact with a service
    from a remote server using `roppy.tubes.tube` which helps you in interacting
    with challenges during Capture The Flag events.

    Example:
          >>> p = remote("localhost", 31337)
          [*] Successfully connected to localhost:31337
          >>> p.recvline()
          b'Address: 0x7ffd4f1f11c0'
          >>> p.sendline("Hello World")
          >>> p.recv()
          b'Echo: You said: Hello\n'
          >>> p.close()
          [*] Connection to localhost:31337 closed
          >>> p.interactive()
          [*] Switching to Interactive mode.
          Address: 0x7ffe57c0c9b0
          Echo: $ helloworld
          You said: helloworld
          $ 
          [*] Got EOF while reading in interactive
          >>> p.close()
          [*] Connection to localhost:31337 closed

    """
    def __init__(self, host, port, timeout=None):
        """Create a socket

        Create a new socket and establish a connection to the host.

        Args:
            host (str): The host name or ip address of the server
            port (int): The port number

        Returns:
            remote: ``Socket`` instance.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        # Create a new socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Establish a connection
        try:
            self.sock.connect((self.host, self.port))
            log.info("Successfully connected to {0}:{1}".format(self.host, self.port))
        except ConnectionRefusedError as e:
            log.warning("Connection to {0}:{1} refused".format(self.host, self.port))

    def _settimeout(self, timeout):
        if timeout is None:
            self.sock.settimeout(self.timeout)
        else:
            self.sock.settimeout(timeout)

    def _socket(self):
        return self.sock
    
    def recv(self, size=4096, timeout=None):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        if size <= 0:
            log.error("`size` must be larger than 0")
            return None
        try:
            data = self.sock.recv(size)
        except socket.timeout:
            return None
        # No data received
        if len(data) == 0:
            data = None
        return data

    def recvonce(self, size=4, timeout=None):
        """Receive raw data at once

        Receive raw data of `size` bytes length through the socket.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        data = b''
        if size <= 0:
            log.error("`size` must be larger than 0")
            return None
        try:
            read_byte = 0
            recv_size = size
            while read_byte < size:
                data += self.sock.recv(recv_size)
                read_byte = len(data)
                recv_size = size - read_byte
        except socket.timeout:
            log.error("Timeout")
            return None
        return data

    def send(self, data, timeout=None):
        """Send raw data

        Send raw data through the socket

        Args:
            data (bytes) : Data to send
            timeout (int): Timeout (in second)
        """
        self._settimeout(timeout)
        if isinstance(data, str):
            data = str2bytes(data)

        try:
            self.sock.send(data)
        except BrokenPipeError:
            log.warning("Broken pipe")

    def close(self):
        """Close the socket

        Close the socket.
        This method is called from the destructor.
        """
        if self.sock:
            self.sock.close()
            self.sock = None
            log.info("Connection to {0}:{1} closed".format(self.host, self.port))

    def shutdown(self, target):
        """Kill one connection

        Close send/recv socket.

        Args:
            target (str): Connection to close (`send` or `recv`)
        """
        if target in ['write', 'send', 'stdin']:
            self.sock.shutdown(socket.SHUT_WR)
        
        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.sock.shutdown(socket.SHUT_RD)

        else:
            log.error("You must specify `send` or `recv` as target.")

    def __del__(self):
        self.close()
