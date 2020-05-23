import binascii


def checkstr(strings):
    try:
        return binascii.unhexlify(strings[2:]).decode("utf-8")
    except:
        return strings


def str2bytes(data):
    return bytes(data, encoding="utf-8")

def bytes2str(data):
    data = "".join(map(chr, data))
    return data

def pause():
    input("Paused [Press any key to continue]")
    return

