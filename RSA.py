
#cifrador RSA, recebe mensagem (inteiro entre 0 e n-1) e uma chave pública (n, e)
def RSA_enc(pub_key, men: int):
    n, e = pub_key

    if not (0 < men and men < n - 1):
        print("representação da mensagem fora de alcance")

    c = pow(men, e, n)

    return c

#decifrador RSA, recebe cifra (inteiro entre 0 e n-1) e uma chave privada (n, d)
def RSA_dec(pri_key, cipher: int):
    n, d = pri_key

    if not (0 < cipher and cipher < n - 1):
        print("representação da cifra fora de alcance")
    
    m = pow(cipher, d, n)

    return m