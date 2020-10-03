from roppylib.util.misc import checkstr
from roppylib.context import context
from roppylib.log import getLogger

log = getLogger(__name__)

def de_bruijn(k, n: int) -> str:
    """
    de Bruijn sequence for alphabet k
    and subsequences of length n.
    """
    alphabet = k
    k = len(k)

    a = [0] * k * n

    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c
            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c
    return db(1, 1)




def cyclic(size, wordsize=context.bytes):
    charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
    res = bytearray()
    for length, char in enumerate(de_bruijn(charset, wordsize)):
        res.append(char)
        if length == size:
            break
    return res


def offset(pattern, wordsize=context.bytes):
    pattern = checkstr(pattern)
    log.info("Searching for {}".format(pattern))

    """ Maximum size is 20230 """
    
    buffer = cyclic(20230, wordsize)
    found = False

    """ Little Endian Search of pattern """
    little_endian = buffer.find(pattern[::-1])
    
    if little_endian >= 0:
        log.info("Found buffer offset at {} [Little Endian]".format(little_endian))
        found = True
        return little_endian
    
    """ Big Endian Search of pattern """
    big_endian = buffer.find(pattern)
    
    if big_endian >= 0:
        log.info("Found buffer offset at {} [Big Endian]".format(big_endian))
        found = True
        return big_endian
    
    if not found:
        log.error("Not found!")