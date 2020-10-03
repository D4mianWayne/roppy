import struct
from roppylib.log import getLogger

log = getLogger(__name__)

def p8(data):
    try:
        return struct.pack("<B", data)
    except Exception as E:
        log.error("%s" %E) 

def p64(data):
    try:
        return struct.pack("<Q", data)
    except Exception as E: 
        log.error("%s" %E) 

def p32(data):
    try:
        return struct.pack("<I", data)
    except Exception as E:
        log.error("%s" %E)

def p16(data):
    try:
        return struct.pack("<H", data)
    except Exception as E:
        log.error("%s" %E) 

def u64(data):
    try:
        data = data.ljust(8, b"\x00")
        return struct.unpack("<Q", data)[0]
    except Exception as E: 
        log.error("%s" %E) 

def u32(data):
    try:
        data = data.ljust(4, b"\x00")
        return struct.unpack("<I", data)[0]
    except Exception as E:
        log.error("%s" %E)

def u16(data):
    try:
        return struct.unpack("<H", ("Could not parse the value."))
    except Exception as E:
        log.error("%s" %E) [0]

def u8(data):
    try:
        return struct.unpack("<B", data)[0]
    except Exception as E:
        log.error("%s" %E) 