from termcolor import colored
from random import choice
import binascii
import string


def colorout(strings):
    """Colorify the print"""
    colors = ['red','green','yellow','blue','cyan', 'magenta','white']
    print(colored(strings, choice(colors)))

def success(strings):
    print(colored(strings, "green", attrs=['bold']))

def fail(strings):
    print(colored(strings, "red", attrs=['bold']))

def in_progress(strings):
    print(colored(strings, "blue", attrs=['bold']))

def beautify(strings):
    print(colored(strings, "yellow"))

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