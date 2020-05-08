import socket
from .tube import *
from ..log import *
from .buffer import Buffer

class remote(Tube):
    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

        self.buffer = Buffer()

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.conn.connect((self.host, self.port))
        except (ConnectionError, ConnectionRefusedError, socket.timeout):
            logger.error("Unable to connect to {0} : {1}".format(self.host, self.port))
        
        logger.info("Connected to {0} : {1}".format(self.host, self.port))

    
    def _settimeout(self, timeout):
        # set timeout for interaction
        if timeout is None:
            self.temp_timeout = self.timeout
        else:
            self.temp_timeout = timeout
    
    def _socket(self):
        return self.conn
    
    def recv_raw(self, size=4096, timeout=None):
        """
        Recieve data from the connection
        """
        self._settimeout(timeout)

        if size <= 0:
            logger.error("`size` value is: {0}, it must be greater than 0".format(size))

        data = b''
        try:
            data = self.conn.recv(size)
        except socket.timeout:
            return None
        
        if len(data) == 0:
            return None
        
        return data
    
    def recvonce(self, size=4, timeout=None):
        """
        Recives data through socket with default size 4.

        Args:
            size    (int): The data size to receive
            timeout (int): Timeout (in second)

        Returns:
            bytes: The received data
        """
        self._settimeout(timeout)
        data = b''
        if size <= 0:
            logger.error("`size` must be larger than 0")
            return None

        read_byte = 0
        recv_size = size
        while read_byte < size:
            recv_data = self.recv_raw(recv_size, timeout)
            if recv_data is None:
                return None
            elif recv_data == b'':
                logger.error("Received nothing")
                return None
            data += recv_data
            read_byte += len(data)
            recv_size = size - read_byte
        return data
    
    def send_raw(self, data, timeout):
        """
        Send data via socket
        
        Arguments:
               data (bytes/str):  Data to be sent.
               timeout (int)   : The timeout
        """

        if isinstance(data, str):
            data = data.encode("latin")
        
        try:
            self.conn.send(data)
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            raise EOFError
    
    def close(self):
        """
        Closes the connection from the host
        """

        try:
            self.conn.close()
            logger.info("Connection from {0}:{1}".format(self.host, self.port))
        except ConnectionError:
            logger.error("Connection already has been closed.")
        
    
    def shutdown(self):
        if target in ['write', 'send', 'stdin']:
            self.conn.shutdown(socket.SHUT_WR)
        
        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.conn.shutdown(socket.SHUT_RD)
        
        else:
            logger.error("The specified option cannot not be closed.")
    
    def __del__(self):
        self.close()