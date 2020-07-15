import configparser
import logging
import os
import random
import sys
import threading
import time

from roppylib import term
from roppylib.context import context
from roppylib.exception import RoplibException
from roppylib.term import spinners
from roppylib.term import text

__all__ = [
    'getLogger', 'install_default_handler', 'rootlogger'
]

# list of prefixes to use for the different message types.  note that the `text`
# module won't add any escape codes if `sys.stderr.isatty()` is `False`
_msgtype_prefixes = {
    'status': [text.magenta, 'x'],
    'success': [text.bold_green, '+'],
    'failure': [text.bold_red, '-'],
    'debug': [text.bold_red, 'DEBUG'],
    'info': [text.bold_blue, '*'],
    'warning': [text.bold_yellow, '!'],
    'error': [text.on_red, 'ERROR'],
    'exception': [text.on_red, 'EXCEPTION'],
    'critical': [text.on_red, 'CRITICAL'],
}


_spinner_style = text.bold_yellow


class Progress:

    def __init__(self, logger, msg, status, level, args, kwargs):
        global _progressid
        self._logger = logger
        self._msg = msg
        self._status = status
        self._level = level
        self._stopped = False
        self.last_status = 0
        self._log(status, args, kwargs, 'status')
        # it is a common use case to create a logger and then immediately update
        # its status line, so we reset `last_status` to accomodate this pattern
        self.last_status = 0

    def _log(self, status, args, kwargs, msgtype):
        # this progress logger is stopped, so don't generate any more records
        if self._stopped:
            return

        msg = self._msg
        if msg and status:
            msg += ': '
        msg += status

        self._logger._log(self._level, msg, args, kwargs, msgtype, self)

    def status(self, status, *args, **kwargs):
        """status(status, *args, **kwargs)

        Logs a status update for the running job.

        If the progress logger is animated the status line will be updated in
        place.

        Status updates are throttled at one update per 100ms.
        """
        now = time.time()
        if (now - self.last_status) > 0.1:
            self.last_status = now
            self._log(status, args, kwargs, 'status')

    def success(self, status='Done', *args, **kwargs):
        """success(status = 'Done', *args, **kwargs)

        Logs that the running job succeeded.  No further status updates are
        allowed.

        If the Logger is animated, the animation is stopped.
        """
        self._log(status, args, kwargs, 'success')
        self._stopped = True

    def failure(self, status='Failed', *args, **kwargs):
        """failure(message)

        Logs that the running job failed.  No further status updates are
        allowed.

        If the Logger is animated, the animation is stopped.
        """
        self._log(status, args, kwargs, 'failure')
        self._stopped = True

    def __enter__(self):
        return self

    def __exit__(self, exc_typ, exc_val, exc_tb):
        # if the progress logger is already stopped these are no-ops
        if exc_typ is None:
            self.success()
        else:
            self.failure()


class Logger:

    _one_time_infos = set()
    _one_time_warnings = set()

    def __init__(self, logger=None):
        if logger is None:

            module = self.__module__
            if not module.startswith('roppylib'):
                module = 'roppylib.' + module
            # - end hack -

            logger_name = '%s.%s.%s' % (module, self.__class__.__name__, id(self))
            logger = logging.getLogger(logger_name)

        self._logger = logger

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):
        extra = kwargs.get('extra', {})
        extra.setdefault('roppylib_msgtype', msgtype)
        extra.setdefault('roppylib_progress', progress)
        kwargs['extra'] = extra
        self._logger.log(level, msg, *args, **kwargs)

    def progress(self, message, status='', *args, **kwargs):

        level = kwargs.pop('level', logging.INFO)
        return Progress(self, message, status, level, args, kwargs)

    def waitfor(self, *args, **kwargs):
        """Alias for :meth:`progress`."""
        return self.progress(*args, **kwargs)

    def indented(self, message, *args, **kwargs):
        """indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        level = kwargs.pop('level', logging.INFO)
        self._log(level, message, args, kwargs, 'indented')

    def success(self, message, *args, **kwargs):
        """success(message, *args, **kwargs)

        Logs a success message.
        """
        self._log(logging.INFO, message, args, kwargs, 'success')

    def failure(self, message, *args, **kwargs):
        """failure(message, *args, **kwargs)

        Logs a failure message.
        """
        self._log(logging.INFO, message, args, kwargs, 'failure')

    # logging functions also exposed by `logging.Logger`

    def debug(self, message, *args, **kwargs):
        """debug(message, *args, **kwargs)

        Logs a debug message.
        """
        self._log(logging.DEBUG, message, args, kwargs, 'debug')

    def info(self, message, *args, **kwargs):
        """info(message, *args, **kwargs)

        Logs an info message.
        """
        self._log(logging.INFO, message, args, kwargs, 'info')

    def hexdump(self, message, *args, **kwargs):
        import roppylib.misc.utils

        self.info(roppylib.misc.utils.hexdump(message, *args, **kwargs))

    def warning(self, message, *args, **kwargs):
        """warning(message, *args, **kwargs)

        Logs a warning message.
        """
        self._log(logging.WARNING, message, args, kwargs, 'warning')

    def warn(self, *args, **kwargs):
        """Alias for :meth:`warning`."""
        return self.warning(*args, **kwargs)

    def error(self, message, *args, **kwargs):
        """error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``RoplibException``.
        """
        self._log(logging.ERROR, message, args, kwargs, 'error')
        raise RoplibException(message % args)

    def exception(self, message, *args, **kwargs):
        """exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        kwargs["exc_info"] = 1
        self._log(logging.ERROR, message, args, kwargs, 'exception')
        raise

    def critical(self, message, *args, **kwargs):
        """critical(message, *args, **kwargs)

        Logs a critical message.
        """
        self._log(logging.CRITICAL, message, args, kwargs, 'critical')

    def log(self, level, message, *args, **kwargs):
        """log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``pwnlib`` formatter will
        use the default :mod:`logging` formater to format this message.
        """
        self._log(level, message, args, kwargs, None)

    def isEnabledFor(self, level):
        """isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        effectiveLevel = self._logger.getEffectiveLevel()

        if effectiveLevel == 1:
            effectiveLevel = context.log_level
        return effectiveLevel <= level

    def setLevel(self, level):
        """setLevel(level)

        Set the logging level for the underlying logger.
        """
        with context.local(log_level=level):
            self._logger.setLevel(context.log_level)

    def addHandler(self, handler):
        """addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        self._logger.addHandler(handler)

    def removeHandler(self, handler):
        """removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        self._logger.removeHandler(handler)

    @property
    def level(self):
        return self._logger.level

    @level.setter
    def level(self, value):
        with context.local(log_level=value):
            self._logger.level = context.log_level


class Handler(logging.StreamHandler):

    def emit(self, record):
        """
        Emit a log record or create/update an animated progress logger
        depending on whether :data:`term.term_mode` is enabled.
        """
        # We have set the root 'pwnlib' logger to have a logLevel of 1,
        # when logging has been enabled via install_default_handler.
        #
        # If the level is 1, we should only process the record if
        # context.log_level is less than the record's log level.
        #
        # If the level is not 1, somebody else expressly set the log
        # level somewhere on the tree, and we should use that value.
        level = logging.getLogger(record.name).getEffectiveLevel()
        if level == 1:
            level = context.log_level
        if level > record.levelno:
            return

        progress = getattr(record, 'roppylib_progress', None)

        # if the record originates from a `Progress` object and term handling
        # is enabled we can have animated spinners! so check that
        if progress is None or not term.term_mode:
            super(Handler, self).emit(record)
            return

        # yay, spinners!

        # since we want to be able to update the spinner we overwrite the
        # message type so that the formatter doesn't output a prefix symbol
        msgtype = record.roppylib_msgtype
        record.roppylib_msgtype = 'animated'
        msg = "%s\n" % self.format(record)

        # we enrich the `Progress` object to keep track of the spinner
        if not hasattr(progress, '_spinner_handle'):
            spinner_handle = term.output('')
            msg_handle = term.output(msg)
            stop = threading.Event()

            def spin():
                '''Wheeeee!'''
                state = 0
                states = random.choice(spinners.spinners)
                while True:
                    prefix = '[%s] ' % _spinner_style(states[state])
                    spinner_handle.update(prefix)
                    state = (state + 1) % len(states)
                    if stop.wait(0.1):
                        break

            t = threading.Thread(target=spin)
            t.daemon = True
            t.start()
            progress._spinner_handle = spinner_handle
            progress._msg_handle = msg_handle
            progress._stop_event = stop
            progress._spinner_thread = t
        else:
            progress._msg_handle.update(msg)

        # if the message type was not a status message update, then we should
        # stop the spinner
        if msgtype != 'status':
            progress._stop_event.set()
            progress._spinner_thread.join()
            style, symb = _msgtype_prefixes[msgtype]
            prefix = '[%s] ' % style(symb)
            progress._spinner_handle.update(prefix)


class Formatter(logging.Formatter):

    # Indentation from the left side of the terminal.
    # All log messages will be indented at list this far.
    indent = '    '

    # Newline, followed by an indent.  Used to wrap multiple lines.
    nlindent = '\n' + indent

    def format(self, record):
        # use the default formatter to actually format the record
        msg = super(Formatter, self).format(record)

        # then put on a prefix symbol according to the message type
        msgtype = getattr(record, 'roppylib_msgtype', None)

        # if 'pwnlib_msgtype' is not set (or set to `None`) we just return the
        # message as it is
        if msgtype is None:
            return msg

        if msgtype in _msgtype_prefixes:
            style, symb = _msgtype_prefixes[msgtype]
            prefix = '[%s] ' % style(symb)
        elif msgtype == 'indented':
            prefix = self.indent
        elif msgtype == 'animated':
            # the handler will take care of updating the spinner, so we will
            # not include it here
            prefix = ''
        else:
            # this should never happen
            prefix = '[?] '

        msg = prefix + msg
        msg = self.nlindent.join(msg.splitlines())
        return msg


# we keep a dictionary of loggers such that multiple calls to `getLogger` with
# the same name will return the same logger
def getLogger(name):
    return Logger(logging.getLogger(name))



def checkLevel(value):
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

#
rootlogger = getLogger('roppylib')
console = Handler(sys.stdout)
formatter = Formatter()
console.setFormatter(formatter)


def install_default_handler():

    console.stream = sys.stdout
    logger = logging.getLogger('roppylib')

    if console not in logger.handlers:
        logger.addHandler(console)

    logger.setLevel(1)
