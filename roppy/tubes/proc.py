import subprocess
import sys
import fcntl
import errno
import select
import os
import tty
import pty
from ..log import *
from .tube import Tube



PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT
PTY = object()

class process(Tube):

    PTY = PTY

    def __init__(self, args, env=None, cwd=None, timeout=None, stdin=PIPE, stdout=PTY, stderr=STDOUT, raw= True, closed_fds=True):
        """
        Create a process instance and pipe 
        it for `Tube`

        Args:
            args (list): The arguments to pass
            env (list) : The environment variables
        """
        super(process, self).__init__()
        if isinstance(args, list):
            self.args = args
            self.fpath = self.args[0]
        else:
            self.args = [args]
            self.fpath = self.args[0]
            
        self.env          = env
        self.timeout      = timeout
        self.cwd          = cwd
        self.raw          = raw
        self.temp_timeout = None
        self.proc = None

        if stderr is STDOUT:
            stderr = stdout
        
        handles = (stdin, stdout, stderr)
        self.pty = handles.index(PTY) if PTY in handles else None

        stdin, stdout, stderr, master, slave = self._handles(*handles)

        try:
            self.proc = subprocess.Popen(
                self.args,
                cwd    = self.cwd,
                env    = self.env,
                shell  = False,
                stdout = stdout,
                stdin  = stdin,
                stderr = stderr,
            )
        
        except FileNotFoundError:
            logger.warn("{} not found.".format(self.fpath))
            return
        
        if self.pty is not None:
            if stdin is slave:
                self.proc.stdin = os.fdopen(os.dup(master), 'r+b', 0)
            if stdout is slave:
                self.proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
            if stderr is slave:
                self.proc.stderr = os.fdopen(os.dup(master), 'r+b', 0)
            
            os.close(master)
            os.close(slave)

        
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        logger.info("Successfully started process. PID - {}".format(self.proc.pid))
    
    def _handles(self, stdin, stdout, stderr):
        master = slave = None

        if self.pty is not None:
            # Normally we could just use subprocess.PIPE and be happy.
            # Unfortunately, this results in undesired behavior when
            # printf() and similar functions buffer data instead of
            # sending it directly.
            #
            # By opening a PTY for STDOUT, the libc routines will not
            # buffer any data on STDOUT.
            master, slave = pty.openpty()

            if self.raw:
                # By giving the child process a controlling TTY,
                # the OS will attempt to interpret terminal control codes
                # like backspace and Ctrl+C.
                #
                # If we don't want this, we set it to raw mode.
                tty.setraw(master)
                tty.setraw(slave)

            if stdin is PTY:
                stdin = slave
            if stdout is PTY:
                stdout = slave
            if stderr is PTY:
                stderr = slave

        return stdin, stdout, stderr, master, slave

    
    def _settimeout(self, timeout):
        # set timeout for interaction
        if timeout is None:
            self.temp_timeout = self.timeout
        else:
            self.temp_timeout = timeout

    def _socket(self):
        # Returns the process instance itself
        return self.proc
    
    def _poll(self):
        if self.proc is None:
            return self.close()

        # Process polling 
        self.proc.poll()
        rcode = self.proc.returncode
        if rcode is not None:
            logger.error(
                "Process {0} stopped with exit code {1}. PID - {2}".format(
                    self.fpath, rcode, self.proc.pid
                )
            )
            self.proc = None
        return rcode
    
    def _is_alive(self):
        #  Checks if process is still alive or not.
        return self._poll() is None

    def _can_recv(self):
        # Check if a process can recieve data or not.

        if self.proc is None:
            return False
        
        try:
            return select.select([self.proc.stdout], [], [], self.temp_timeout) == select.select([self.proc.stdout], [], [])
        except select.error as e:
            if e[0] == errno.EINTR:
                return False
            
    def recv_raw(self, numb, timeout):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self._poll()
        self._settimeout(timeout)
        if not self._can_recv():
            return b''

        # This will only be reached if we either have data,
        # or we have reached an EOF. In either case, it
        # should be safe to read without expecting it to block.
        data = b''

        try:
            data = self.proc.stdout.read(numb)
        except IOError:
            pass

        if not data:
            self.shutdown("recv")
            raise EOFError

        return data

    def recvonce(self, size=4, timeout=None):
        """
        Recives data through pipe.

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
    

    def send_raw(self, data, timeout=None):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self._settimeout(timeout)
        self._poll()


        if isinstance(data, str):
            data = data.encode("latin")
        
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (IOError, AttributeError):
            raise EOFError

            
    
    def close(self):
        """
        Close the process instance
        """
        if self.proc is None:
            return 
        
        self._poll()

        if self.proc:
            self.proc.kill()
            self.proc.wait()
            self.proc = None
            logger.info("Closed process with PID: {}".format(self.proc.pid))

    
    def shutdown(self, target):
        """
        Kill connection by closing the send/recv
        Pipe communication

        Args:
            target (str): Connection to close (`send`, `recv`)
        """

        if target in ['write', 'send', 'stdin']:
            self.proc.stdin.close()
        
        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.proc.stdout.close()
        
        else:
            logger.error("The specified target cannot not be closed.")
        
    
    def __del__(self):
        self.close()