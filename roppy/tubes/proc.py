import logging
from .tube import *
import errno
import select
import fcntl
import os
import tty
import pty
import subprocess
from roppy.log import log
from roppy.misc.utils import str2bytes

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
        self.reservoir    = b''
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
            log.error("{} not found.".format(self.fpath))
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
        log.info("Successfully started process. PID - {}".format(self.proc.pid))
    
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
        if timeout is None:
            self.temp_timeout = self.timeout
        else:
            self.temp_timeout = timeout

    def _socket(self):
        return self.proc

    def _poll(self):
        if self.proc is None:
            return False

        self.proc.poll()
        returncode = self.proc.returncode
        if returncode is not None:
            log.info(
                "Process '{}' stopped with exit code {} (PID={})".format(
                    self.fpath, returncode, self.proc.pid
                ))
            self.proc = None
        return returncode

    def _is_alive(self):
        return self._poll() is None

    def _can_recv(self):
        if self.proc is None:
            return False

        try:
            return select.select([self.proc.stdout], [], [], self.temp_timeout) == ([self.proc.stdout], [], [])
        except select.error as v:
            if v[0] == errno.EINTR:
                return False

    def recv(self, size=4096, timeout=None):
        """Receive raw data

        Receive raw data of maximum `size` bytes length through the pipe.

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

        if not self._can_recv():
            return b''

        data = b''
        try:
            data = self.proc.stdout.read(size)

        except:
            raise EOFError


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
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except IOError:
            log.info("Broken pipe")

        return data

    def close(self):
        """Close the socket

        Close the socket.
        This method is called from the destructor.
        """
        if self.proc:
            self.proc.kill()
            self.proc = None
            log.info("close: '{0}' killed".format(self.fpath))

    def shutdown(self, target):
        """Kill one connection

        Close send/recv pipe.

        Args:
            target (str): Connection to close (`send` or `recv`)
        """
        if target in ['write', 'send', 'stdin']:
            self.proc.stdin.close()

        elif target in ['read', 'recv', 'stdout', 'stderr']:
            self.proc.stdout.close()

        else:
            print("You must specify `send` or `recv` as target.")

    def __del__(self):
        self.close()
