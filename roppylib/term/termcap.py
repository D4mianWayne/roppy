import curses
import os

__all__ = ['get']

cache = None


def get(cap, *args, **kwargs):
    default = kwargs.pop('default', b'')

    if 'PWNLIB_NOTERM' in os.environ:
        return default

    if kwargs != {}:
        raise TypeError("get(): No such argument %r" % kwargs.popitem()[0])

    if cache is None:
        init()

    s = cache.get(cap)
    if not s:
        s = curses.tigetstr(cap)
        if s is None:
            s = curses.tigetnum(cap)
            if s == -2:
                s = curses.tigetflag(cap)
                if s == -1:
                    s = default
                else:
                    s = bool(s)
        cache[cap] = s

    # if `s' is not set `curses.tparm' will throw an error if given arguments
    if args and s:
        return curses.tparm(s, *args)
    else:
        return s


def init():
    global cache

    if 'PWNLIB_NOTERM' not in os.environ:
        # Fix for BPython
        try:
            curses.setupterm()
        except:
            pass

    cache = {}
