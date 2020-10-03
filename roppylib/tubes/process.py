import ctypes
import errno
import fcntl
import logging
import os
import pty
import resource
import select
import subprocess
import tty

from roppylib.context import context
from roppylib.log import getLogger
from roppylib.timeout import Timeout
from roppylib.util.misc import which
from roppylib.util.misc import parse_ldd_output
from roppylib.tubes.tube import tube

log = getLogger(__name__)

PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT
PTY = object()


class process(tube):

    PIPE = PIPE
    STDOUT = STDOUT
    PTY = PTY

    #: Have we seen the process stop?
    _stop_noticed = False

    def __init__(self, argv,
                 shell=False,
                 executable=None,
                 cwd=None,
                 env=None,
                 timeout=Timeout.default,
                 stdin=PIPE,
                 stdout=PTY,
                 stderr=STDOUT,
                 level=None,
                 close_fds=True,
                 preexec_fn=lambda: None,
                 raw=True,
                 aslr=None,
                 setuid=None):
        super(process, self).__init__(timeout, level=level)

        #: `subprocess.Popen` object
        self.proc = None

        if not shell:
            executable, argv, env = self._validate(cwd, executable, argv, env)

        # Permit invocation as process('sh') and process(['sh'])
        if isinstance(argv, (bytes, str)):
            argv = [argv]

        # Avoid the need to have to deal with the STDOUT magic value.
        if stderr is STDOUT:
            stderr = stdout

        # Determine which descriptors will be attached to a new PTY
        handles = (stdin, stdout, stderr)

        #: Which file descriptor is the controlling TTY
        self.pty = handles.index(PTY) if PTY in handles else None

        #: Whether the controlling TTY is set to raw mode
        self.raw = raw

        #: Whether ASLR should be left on
        self.aslr = aslr if aslr is not None else context.aslr

        #: Whether setuid is permitted
        self._setuid = setuid if setuid is None else bool(setuid)

        # Create the PTY if necessary
        stdin, stdout, stderr, master, slave = self._handles(*handles)

        #: Full path to the executable
        self.executable = executable

        #: Arguments passed on argv
        self.argv = argv

        #: Environment passed on envp
        self.env = env or os.environ

        #: Directory the process was created in
        self.cwd = cwd or os.path.curdir

        self.preexec_fn = preexec_fn

        message = "Starting program %r" % self.program

        if self.isEnabledFor(logging.DEBUG):
            if self.argv != [self.executable]:
                message += ' argv=%r ' % self.argv
            if self.env != os.environ:
                message += ' env=%r ' % self.env

        with self.progress(message) as p:

            prefixes = [([], executable)]
            exception = None

            for prefix, executable in prefixes:
                try:
                    self.proc = subprocess.Popen(args=prefix + argv,
                                                 shell=shell,
                                                 executable=executable,
                                                 cwd=cwd,
                                                 env=env,
                                                 stdin=stdin,
                                                 stdout=stdout,
                                                 stderr=stderr,
                                                 close_fds=close_fds,
                                                 preexec_fn=self._preexec_fn)
                    p.success("PID %d" %(self.proc.pid))
                    break
                except OSError as e:
                    exception = e
                    if exception.errno != errno.ENOEXEC:
                        raise
            else:
                try:
                    raise exception
                except:
                    self.exception(str(prefixes))

        if self.pty is not None:
            if stdin is slave:
                self.proc.stdin = os.fdopen(os.dup(master), 'r+b', 0)
            if stdout is slave:
                self.proc.stdout = os.fdopen(os.dup(master), 'r+b', 0)
            if stderr is slave:
                self.proc.stderr = os.fdopen(os.dup(master), 'r+b', 0)

            os.close(master)
            os.close(slave)

        # Set in non-blocking mode so that a call to call recv(1000) will
        # return as soon as a the first byte is available
        fd = self.proc.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def _preexec_fn(self):
        """
        Routine executed in the child process before invoking execve().

        Handles setting the controlling TTY as well as invoking the user-
        supplied preexec_fn.
        """
        if self.pty is not None:
            self._pty_make_controlling_tty(self.pty)

        if not self.aslr:
            try:
                if context.os == 'linux' and self._setuid is not True:
                    ADDR_NO_RANDOMIZE = 0x0040000
                    ctypes.CDLL('libc.so.6').personality(ADDR_NO_RANDOMIZE)

                resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))
            except:
                log.exception("Could not disable ASLR")

        # Assume that the user would prefer to have core dumps.
        resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))

        # Given that we want a core file, assume that we want the whole thing.
        try:
            with open('/proc/self/coredump_filter', 'w') as f:
                f.write('0xff')
        except Exception:
            pass

        if self._setuid is False:
            try:
                PR_SET_NO_NEW_PRIVS = 38
                ctypes.CDLL('libc.so.6').prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            except:
                pass

        self.preexec_fn()

        try:
            PR_SET_PTRACER = 0x59616d61
            PR_SET_PTRACER_ANY = -1
            ctypes.CDLL('libc.so.6').prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
        except Exception:
            pass

    @property
    def program(self):
        """Alias for ``executable``, for backward compatibility"""
        return self.executable

    @staticmethod
    def _validate(cwd, executable, argv, env):
        """
        Perform extended validation on the executable path, argv, and envp.

        Mostly to make Python happy, but also to prevent common pitfalls.
        """
        cwd = cwd or os.path.curdir

        #
        # Validate argv
        #
        # - Must be a list/tuple of strings
        # - Each string must not contain '\x00'
        #
        if isinstance(argv, (bytes, str)):
            argv = [argv]

        if not all(isinstance(arg, (bytes, str)) for arg in argv):
            log.error("argv must only contain bytes or strings: %r" % argv)

        # Create a duplicate so we can modify it
        argv = list(argv or [])

        for i, arg in enumerate(argv):
            null_byte = b'\x00' if isinstance(arg, bytes) else '\x00'
            if null_byte in arg[:-1]:
                log.error('Inappropriate nulls in argv[%i]: %r' % (i, arg))

            argv[i] = arg.rstrip(null_byte)

        #
        # Validate executable
        #
        # - Must be an absolute or relative path to the target executable
        # - If not, attempt to resolve the name in $PATH
        #
        if not executable:
            if not argv:
                log.error("Must specify argv or executable")
            executable = argv[0]

        # Do not change absolute paths to binaries
        if executable.startswith(os.path.sep):
            pass

        # If there's no path component, it's in $PATH or relative to the
        # target directory.
        #
        # For example, 'sh'
        elif os.path.sep not in executable and which(executable):
            executable = which(executable)

        # Either there is a path component, or the binary is not in $PATH
        # For example, 'foo/bar' or 'bar' with cwd=='foo'
        elif os.path.sep not in executable:
            executable = os.path.join(cwd, executable)

        if not os.path.exists(executable):
            log.error("%r does not exist" % executable)
        if not os.path.isfile(executable):
            log.error("%r is not a file" % executable)
        if not os.access(executable, os.X_OK):
            log.error("%r is not marked as executable (+x)" % executable)

        #
        # Validate environment
        #
        # - Must be a dictionary of {string:string}
        # - No strings may contain '\x00'
        #

        # Create a duplicate so we can modify it safely
        env = dict(env or os.environ)
        env_vars = env.items()
        env = {}
        for k, v in env_vars:
            if not isinstance(k, (bytes, str)):
                log.error('Environment keys must be bytes or strings: %r' % k)
            if not isinstance(v, (bytes, str)):
                log.error('Environment values must be bytes or strings: %r=%r' % (k, v))

            k_null_byte = b'\x00' if isinstance(k, bytes) else '\x00'
            v_null_byte = b'\x00' if isinstance(v, bytes) else '\x00'

            if k_null_byte in k[:-1]:
                log.error('Inappropriate null byte in env key: %r' % k)
            if v_null_byte in v[:-1]:
                log.error('Inappropriate null byte in env value: %r=%r' % (k, v))

            env[k.rstrip(k_null_byte)] = v.rstrip(v_null_byte)

        return executable, argv, env

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

    def __getattr__(self, attr):
        """Permit pass-through access to the underlying process object for
        fields like ``pid`` and ``stdin``.
        """
        if hasattr(self.proc, attr):
            return getattr(self.proc, attr)

        raise AttributeError("'process' object has no attribute '%s'" % attr)

    def kill(self):
        """kill()

        Kills the process.
        """
        self.close()

    def poll(self, block=False):
        """poll(block=False) -> int

        Arguments:
            block(bool): Wait for the process to exit

        Poll the exit code of the process. Will return None, if the
        process has not yet finished and the exit code otherwise.
        """
        if block:
            self.wait_for_close()

        self.proc.poll()

        if self.proc.returncode is not None and not self._stop_noticed:
            self._stop_noticed = True
            self.info("Program %r stopped with exit code %d" %
                      (self.program, self.proc.returncode))

        return self.proc.returncode

    # Implementation of the methods required for tube
    def recv_raw(self, numb):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self.poll()

        if not self.connected_raw('recv'):
            raise EOFError

        if not self.can_recv_raw(self.timeout):
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

    def send_raw(self, data):
        # This is a slight hack. We try to notice if the process is
        # dead, so we can write a message.
        self.poll()

        if not self.connected_raw('send'):
            raise EOFError

        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except IOError:
            raise EOFError

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        if not self.connected_raw('recv'):
            return False

        try:
            if timeout is None:
                return select.select([self.proc.stdout], [], []) == ([self.proc.stdout], [], [])

            return select.select([self.proc.stdout], [], [], timeout) == ([self.proc.stdout], [], [])
        except OSError:
            # Not sure why this isn't caught when testing self.proc.stdout.closed,
            # but it's not.
            #
            #   File "$PATH/tubes/process.py", line 112, in can_recv_raw
            #     return select.select([self.proc.stdout], [], [], timeout) == ([self.proc.stdout], [], [])
            # ValueError: I/O operation on closed file
            raise EOFError
        except select.error as v:
            if v[0] == errno.EINTR:
                return False

    def connected_raw(self, direction):
        if direction == 'any':
            return self.poll() is None
        elif direction == 'send':
            return not self.proc.stdin.closed
        elif direction == 'recv':
            return not self.proc.stdout.closed

    def close(self):
        if self.proc is None:
            return

        # First check if we are already dead
        self.poll()

        # close file descriptors
        for fd in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if fd is not None:
                fd.close()

        if not self._stop_noticed:
            try:
                self.proc.kill()
                self.proc.wait()
                self._stop_noticed = True
                self.info('Stopped program %r' % self.program)
            except OSError:
                pass

    def fileno(self):
        if not self.connected():
            self.error("A stopped program does not have a file number")

        return self.proc.stdout.fileno()

    def shutdown_raw(self, direction):
        if direction == "send":
            self.proc.stdin.close()

        if direction == "recv":
            self.proc.stdout.close()

        if False not in (self.proc.stdin.closed, self.proc.stdout.closed):
            self.close()

    def _pty_make_controlling_tty(self, tty_fd):
        '''This makes the pseudo-terminal the controlling tty. This should be
        more portable than the pty.fork() function. Specifically, this should
        work on Solaris. '''

        child_name = os.ttyname(tty_fd)

        # Disconnect from controlling tty. Harmless if not already connected.
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            if fd >= 0:
                os.close(fd)
        except OSError:
            pass  # Already disconnected. This happens if running inside cron.

        os.setsid()

        # Verify we are disconnected from controlling tty
        # by attempting to open it again.
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            if fd >= 0:
                os.close(fd)
                raise Exception('Failed to disconnect from controlling tty. '
                                'It is still possible to open /dev/tty.')
        except OSError:
            pass  # Good! We are disconnected from a controlling tty.

        # Verify we can open child pty.
        fd = os.open(child_name, os.O_RDWR)
        if fd < 0:
            raise Exception("Could not open child pty, %s" % child_name)
        else:
            os.close(fd)

        # Verify we now have a controlling tty.
        fd = os.open("/dev/tty", os.O_WRONLY)
        if fd < 0:
            raise Exception("Could not open controlling tty, /dev/tty")
        else:
            os.close(fd)
