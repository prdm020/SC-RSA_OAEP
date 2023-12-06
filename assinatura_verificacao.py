import hashlib as h
import RSA_OAEP as oaep
import base64

# Recebe uma mensagem e assina ela com sua chave privada
def assinatura(mensagem, chave_pri):
    hashM = h.sha3_224(mensagem).digest()

    cifra_hashM = oaep.RSA_OLAP_enc(chave_pri, hashM)

    mensagem_assinada = base64.b64encode(cifra_hashM)

    return mensagem_assinada

# Recebe uma mensagem assinada, decodifica ela com a chave publica. Caso a mensagem 
# gerada não for igual a original, retorna false. Caso o contrário, retorna true
def verificacao(assinatura, chave_pub, mensagem_original):
    hashM_original = h.sha3_224(mensagem_original).digest()

    cifra_hashM = base64.b64decode(assinatura)

    hashM = oaep.RSA_OLAP_dec(chave_pub, cifra_hashM)

    if hashM == hashM_original:
        return True
    else:
        return False
