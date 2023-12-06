import hashlib as h
import random
import utils
import RSA

def RSA_OLAP_enc(public_key, mensagem, label=""):
    n, e = public_key
    label = label.encode()

    if len(label) > ((2^61) - 1):
        print("label muito grande")
        return None
    
    lHash = h.sha1(label).digest()

    k = len(utils.int_bytes(n))

    C = b''
    i = 0
    acabou = False
    while not acabou:
        if (i + 1)*(k - 2*len(lHash) - 2) > len(mensagem):
            block = mensagem[i*(k - 2*len(lHash) - 2):len(mensagem)]
            acabou = True
        else:
            block = mensagem[i*(k - 2*len(lHash) - 2):(i + 1)*(k - 2*len(lHash) - 2)]

        ps = utils.padding_zeros(k - len(block) - 2*len(lHash) - 2)

        DB = lHash + ps + b'\x01' + block

        seed = utils.int_bytes(random.getrandbits(8*len(lHash)), len(lHash))

        dbMask = utils.mgf1(seed, k - len(lHash) - 1)

        maskedDB = utils.xor_bytes(DB, dbMask, k - len(lHash) - 1)

        seedMask = utils.mgf1(maskedDB, len(lHash))

        maskedSeed = utils.xor_bytes(seed, seedMask, len(lHash))

        EM = b'\x00' + maskedSeed + maskedDB

        m = utils.bytes_int(EM)

        c = RSA.RSA_enc(public_key, m)

        C += utils.int_bytes(c, k)

        i += 1

    return C

def RSA_OLAP_dec(private_key, cifra, label=""):
    n, d = private_key
    label = label.encode()

    if len(label) > ((2^61) - 1):
        print("erro de descriptografia\n")
        return None
    
    k = len(utils.int_bytes(n))

    acabou = False
    M = b''
    j = 0
    while not acabou:
        if (j + 1)*k == len(cifra):
            acabou = True
        if (j + 1)*k <= len(cifra):
            block = cifra[j*k: (j + 1)*k]
        else:
            print("erro de descriptografia\n")
            return None
    
        lHash = h.sha1(label).digest()

        if k < 2*len(lHash) + 2:
            print("erro de descriptografia\n")
            return None

        c = utils.bytes_int(block)

        m = RSA.RSA_dec(private_key, c)

        EM = utils.int_bytes(m, k)

        if EM[0] != 0:
            print("erro de descriptografia\n")
            return None

        maskedSeed = EM[1:1 + len(lHash)]

        maskedDB = EM[1 + len(lHash):]

        seedMask = utils.mgf1(maskedDB, len(lHash))

        seed = utils.xor_bytes(maskedSeed, seedMask, len(lHash))

        dbMask = utils.mgf1(seed, k - len(lHash) - 1)

        DB = utils.xor_bytes(maskedDB, dbMask, k - len(lHash) - 1)

        if DB[:len(lHash)] != lHash:
            print("erro de descriptografia\n")
            return None

        i = len(lHash)
        while True:
            if DB[i] == 0:
                i += 1
                continue
            elif DB[i] == 1:
                break
            else:
                print("erro de descriptografia\n")
                return None
        M += DB[i+1:]
        j += 1
    return M

    
