import hashlib as h

#recebe um inteiro e retorna um array de bytes associado
def int_bytes(n: int, tamanho=0):
    
    if tamanho == 0:
        while True:
            tamanho += 1
            try:
                return n.to_bytes(tamanho,'big')
            except OverflowError:
                continue
    return n.to_bytes(tamanho,'big')
    
#recebe um array de bytes e retorna o inteiro associado
def bytes_int(b: bytes):
    return int.from_bytes(b, 'big')

#recebe um inteiro n e retorna n bytes com zeros
def padding_zeros(n: int):
    zero = 0
    return zero.to_bytes(n, 'big')

#Mask Generation Function
def mgf1(seed: bytes, length: int, hash_func=h.sha1):
    hLen = hash_func().digest_size

    if length > (hLen << 32):
        raise ValueError("mask too long")
    
    T = b""
    counter = 0
    while len(T) < length:
        C = int_bytes(counter, 4)
        T += hash_func(seed + C).digest()
        counter += 1

    return T[:length]

def xor_bytes(a: bytes, b: bytes, tamanho=0):
    ia = bytes_int(a)
    ib = bytes_int(b)
    aux = ia ^ ib
    return int_bytes(aux, tamanho)