import binascii
from roppylib.term import getkey
from roppylib.log import getLogger

log = getLogger(__name__)

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
    if isinstance(data, str):
      return bytes(data, encoding="utf8")
    else:
      return data
    
def bytes2str(data):
    """
    Convert bytes to string
    >>> bytes2str(b'Pwning')
    'Pwning'
    >>> 
    """
    data = "".join(map(chr, data))
    return data

def hexdump(src, length=16, sep='.'):
  """
  >>> print(hexdump('\x01\x02\x03\x04AAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBB'))
  00000000:  01 02 03 04 41 41 41 41  41 41 41 41 41 41 41 41  |....AAAAAAAAAAAA|
  00000010:  41 41 41 41 41 41 41 41  41 41 41 41 41 41 42 42  |AAAAAAAAAAAAAABB|
  00000020:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  |BBBBBBBBBBBBBBBB|
  00000030:  42 42 42 42 42 42 42 42                           |BBBBBBBB|
  >>>
  >>> print(hexdump(b'\x01\x02\x03\x04AAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBB'))
  00000000:  01 02 03 04 41 41 41 41  41 41 41 41 41 41 41 41  |....AAAAAAAAAAAA|
  00000010:  41 41 41 41 41 41 41 41  41 41 41 41 41 41 42 42  |AAAAAAAAAAAAAABB|
  00000020:  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  |BBBBBBBBBBBBBBBB|
  00000030:  42 42 42 42 42 42 42 42                           |BBBBBBBB|
  """
  FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
  lines = []
  for c in range(0, len(src), length):
    chars = src[c:c+length]
    hexstr = ' '.join(["%02x" % ord(x) for x in chars]) if type(chars) is str else ' '.join(['{:02x}'.format(x) for x in chars])
    if len(hexstr) > 24:
      hexstr = "%s %s" % (hexstr[:24], hexstr[24:])
    printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars]) if type(chars) is str else ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
    lines.append("%08x:  %-*s  |%s|" % (c, length*3, hexstr, printable))
  return '\n'.join(lines)

def pause():
    """
    This allows you to pause the program and then attach it to debugger.
    TODO: Make it more sophisticated
    """
    log.info("Paused [Press any key to continue]")
    getkey()
    return

