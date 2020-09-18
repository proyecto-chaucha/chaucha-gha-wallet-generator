"""
Cryptographic functions
"""
import uuid
import secrets

from hashlib import new, sha3_256
from binascii import a2b_hex
from collections import deque

CHAUCHA_PUBKEY_ADDRESS = 58
CHAUCHA_SECRETKEY = 'd8'
digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# https://bitcoin.stackexchange.com/a/59806
def secp256k1(s):
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1

    def add(p, q):
        px, py = p
        qx, qy = q
        if p == q:
            lam = (3 * pow(px, 2)) * pow(2 * py, P - 2, P)
        else:
            lam = (qy - py) * pow(qx - px, P - 2, P)
        rx = lam**2 - px - qx
        ry = lam * (px - rx) - py
        return rx % P, ry % P

    ret = None

    for i in range(256):
        if int(s, 16) & (1 << i):
            ret = G if ret == None else add(ret, G)
        G = add(G, G)

    return '04' + '{:064x}'.format(ret[0]) + '{:064x}'.format(ret[1])

# alias of secp256k1
def getpublic(privkey):
    return secp256k1(privkey)

# https://github.com/joeblackwaslike/base58check
def b58check(val):
    charset = digits58.encode('utf-8')
    output = b''
    p, acc = 1, 0
    pal_stripped = val.lstrip(b'\x00')
    pad_len = len(val) - len(pal_stripped)
    for char in deque(reversed(pal_stripped)):
        acc += p * char
        p = p << 8
    while acc:
        acc, idx = divmod(acc, len(charset))
        output = charset[idx:idx+1] + output
    prefix = bytes([charset[0]]) * pad_len
    return prefix + output

def doubleSHA256(s):
    return new('sha256', new('sha256', a2b_hex(s)).digest()).hexdigest()

def hash160(s):
    return new('ripemd160', new('sha256', a2b_hex(s)).digest()).hexdigest()

def sha3_hex(s):
    return sha3_256(s.encode('utf-8')).hexdigest()

def sha3_bin(s):
    return sha3_256(s.encode('utf-8')).digest()

def decode_base58(bc, length):
    n = 0
    for char in bc:
        n = n * 58 + digits58.index(char)
    return n.to_bytes(length, 'big')

def check_address(bc):
    # http://rosettacode.org/wiki/Bitcoin/address_validation#Python
    try:
        bcbytes = decode_base58(bc, 25)
        return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
    except Exception:
        return False

def uid(length = 32):
    return str(uuid.uuid4()) + secrets.token_hex(length)


