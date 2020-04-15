from rop.misc.utils import *

def de_bruijn(k, n: int) -> str:
    """
    de Bruijn sequence for alphabet k
    and subsequences of length n.
    """
    alphabet = k
    k = len(k)

    a = [0] * k * n
    sequence = []

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



class Pattern(object):
    @classmethod
    def generate_cyclic(cls, size, wordsize):
        charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
        res = bytearray()
        for length, char in enumerate(de_bruijn(charset, wordsize)):
            res.append(char)
            if length == size:
                break
        return res.decode("utf-8")

    @classmethod
    def offset(cls, pattern, wordsize, endian):
        pattern = checkstr(pattern)
        in_progress("[*] Searching for {}".format(pattern))
        """ Maximum size is 20230 """
        cyclic = Pattern.generate_cyclic(20230, wordsize)
        found = False
        """ Little Endian Search of pattern """
        if endian == "little":
            little_endian = cyclic.find(pattern[::-1])
            if little_endian >= 0:
                success("[+] Found buffer offset at {} [Little Endian]".format(little_endian))
                found = True
        """ Big Endian Search of pattern """
        if endian == "big":
            big_endian = cyclic.find(pattern)
            if big_endian >= 0:
                success("[+] Found buffer offset at {} [Big Endian]".format(big_endian))
                found = True
        if not found:
            fail("Not found!")
        return None