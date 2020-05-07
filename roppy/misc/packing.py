import struct


def p8(data):
    try:
        return struct.pack("<B", data)
    except:
        raise ("Could not parse the value.")

def p64(data):
    try:
        return struct.pack("<Q", data)
    except: 
        raise ("Could not parse the value.")

def p32(data):
    try:
        return struct.pack("<I", data)
    except:
        return ("Could not parse the value.")

def p16(data):
    try:
        return struct.pack("<H", data)
    except:
        raise ("Could not parse the value.")

def u64(data):
    try:
        return struct.unpack("<Q", data)[0]
    except: 
        raise ("Could not parse the value.")

def u32(data):
    try:
        return struct.unpack("<I", data)[0]
    except:
        return ("Could not parse the value.")

def u16(data):
    try:
        return struct.unpack("<H", ("Could not parse the value."))
    except:
        raise ("Could not parse the value.")[0]

def u8(data):
    try:
        return struct.unpack("<B", data)[0]
    except:
        raise ("Could not parse the value.")