import binascii
from roppy.log import log

def checkstr(strings):
    try:
        return binascii.unhexlify(strings[2:]).decode("utf-8")
    except:
        return strings


def str2bytes(data):
    """
    Converts string to bytes.
    >>> str2bytes("Pwning")
    b'Pwning'
    """
    return bytes(data, encoding="utf-8")

def bytes2str(data):
    """
    Convert bytes to string
    >>> bytes2str(b'Pwning')
    'Pwning'
    >>> 
    """
    data = "".join(map(chr, data))
    return data

def pause():
    """
    This allows you to pause the program and then attach it to debugger.
    Note: There is a bug that it only attachs to `gdb` if it is spawned by the root 
    itself.
    """
    log.info("Paused [Press any key to continue]")
    input('')
    return

