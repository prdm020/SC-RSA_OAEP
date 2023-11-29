import key_gen as key
import RSA_OAEP as oaep
import utils as u

with open("teste.txt", "rb") as a:
    mensagem = a.read()

    for i in range(20):
        print(f"teste {i + 1}")
        chave_publica, chave_privada = key.gen_keys()

        cifra = oaep.RSA_OLAP_enc(chave_publica, mensagem, "oi tudo bem")

        decifra = oaep.RSA_OLAP_dec(chave_privada, cifra, "oi tudo bem")

        if mensagem == decifra:
            print("deu certo :)")
        else:
            print("deu ruim")
        print()

    a.close



