import sys
import traceback

__all__ = ['RoplibException']


class RoplibException(Exception):
    '''
    A custom exception to take care of 
    internal errors and exception.
    '''

    def __init__(self, message, reason=None, exit_code=None):
        self.message = message
        self.reason = reason
        self.exit_code = exit_code

    def __repr__(self):
        s = 'RoplibException: %s' % self.message

        if self.reason:
            s += '\nReason:\n'
            s += ''.join(traceback.format_exception(*self.reason))
        elif sys.exc_info()[0] not in (None, KeyboardInterrupt):
            s += '\n'
            s += traceback.format_exc()

        return s
