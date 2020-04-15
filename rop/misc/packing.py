import struct


def _lb_wrapper(func):
    bits = int(func.__name__[1:])
    pfs = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}
    def wrapper(*args, fmt="l"):
        endian = "<" if fmt == 'l' else '>'
        ret = []
        join = False
        for i in args:
            if isinstance(i, int):
                join = True
                v = struct.pack(endian + pfs[bits], i % (1 << bits))
                ret.append(v)
            else:
                if not i: 
                    ret.append(None)
                else:
                    v = struct.unpack(endian + pfs[bits] * (len(i) * 8/bits), i)
                    ret += v
        if join:
            return b''.join(ret)
        elif len(ret) == 1:
            return ret[0]
        elif len(ret) == 0:     # all of the input are empty strings
            return None
        else:
            return ret
    wrapper.__name__ = func.__name__
    return wrapper

@_lb_wrapper
def p8(*args, **kwargs): pass
@_lb_wrapper
def p16(*args, **kwargs): pass
@_lb_wrapper
def p32(*args, **kwargs): pass
@_lb_wrapper
def p64(*args, **kwargs): pass


def u64(data):
    try:
        return struct.unpack("<Q", data)
    except: 
        raise ("Could not parse the value.")

def u32(data):
    try:
        return struct.unpack("<I", data)
    except:
        return ("Could not parse the value.")

def u16(data):
    try:
        return struct.unpack("<H", ("Could not parse the value."))
    except:
        raise ("Could not parse the value.")

def u8(data):
    try:
        return struct.unpack("<B", data)
    except:
        raise ("Could not parse the value.")