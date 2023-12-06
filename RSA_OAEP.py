import hashlib as h
import random
import utils
import RSA

def RSA_OLAP_enc(public_key, mensage, label=""):
    n, e = public_key
    label = label.encode()

    if len(label) > ((2^61) - 1):
        print("label muito grande")
        return None
    
    lHash = h.sha1(label).digest()

    k = len(utils.int_bytes(n))

    print(f"tamanho n: {k}")
    print(f"tamanho mensagem: {len(mensage)}")
    print(f"tamanho hlen: {len(lHash)}")
    if len(mensage) > k - 2*len(lHash) - 2:
        print("mensagem muito grande")
        return None

    ps = utils.padding_zeros(k - len(mensage) - 2*len(lHash) - 2)

    DB = lHash + ps + b'\x01' + mensage

    seed = utils.int_bytes(random.getrandbits(8*len(lHash)), len(lHash))

    dbMask = utils.mgf1(seed, k - len(lHash) - 1)

    maskedDB = utils.xor_bytes(DB, dbMask, k - len(lHash) - 1)

    seedMask = utils.mgf1(maskedDB, len(lHash))

    maskedSeed = utils.xor_bytes(seed, seedMask, len(lHash))

    EM = b'\x00' + maskedSeed + maskedDB

    m = utils.bytes_int(EM)

    c = RSA.RSA_enc(public_key, m)

    C = utils.int_bytes(c, k)

    return C

def RSA_OLAP_dec(private_key, cifra, label=""):
    n, d = private_key
    label = label.encode()

    if len(label) > ((2^61) - 1):
        print("erro de descriptografia")
        return None
    
    k = len(utils.int_bytes(n))

    if len(cifra) != k:
        print("erro de descriptografia")
        return None
    
    lHash = h.sha1(label).digest()

    if k < 2*len(lHash) + 2:
        print("erro de descriptografia")
        return None
    
    c = utils.bytes_int(cifra)

    m = RSA.RSA_dec(private_key, c)

    EM = utils.int_bytes(m, k)

    if EM[0] != 0:
        print("erro de descriptografia")
        return None

    maskedSeed = EM[1:1 + len(lHash)]

    maskedDB = EM[1 + len(lHash):]

    seedMask = utils.mgf1(maskedDB, len(lHash))

    seed = utils.xor_bytes(maskedSeed, seedMask, len(lHash))

    dbMask = utils.mgf1(seed, k - len(lHash) - 1)

    DB = utils.xor_bytes(maskedDB, dbMask, k - len(lHash) - 1)

    if DB[:len(lHash)] != lHash:
        print("erro de descriptografia")
        return None
    
    i = len(lHash)
    while True:
        if DB[i] == 0:
            i += 1
            continue
        elif DB[i] == 1:
            break
        else:
            print("erro de descriptografia")
            return None

    return DB[i+1:]

    
