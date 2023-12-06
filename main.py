import key_gen as key
import RSA_OAEP as oaep
import utils as u
import assinatura_verificacao as av

if __name__ == "__main__":

    acao = ""

    print("Bem vindo ao gerador e verificador de assinaturas\n")
    print("obs: as chaves pública e privada são geradas automaticamente. As ações irão utilizar automaticamente essas chaves. Caso queira mudar as chaves basta selecionar a ação 5, porem as chaves antigas serão perdidas.\n")
    chave_publica, chave_privada = key.gen_keys()
    print()

    while True:
        print("(1): Cifrar RSA OLAEP----(utiliza chave publica)")
        print("(2): Decifrar RSA OLAEP--(utiliza chave privada)")
        print("(3): Assinar-------------(utiliza chave privada)")
        print("(4): Verificar-----------(utiliza chave publica)")
        print("(5): Gerar novas chaves")
        print("(6): Sair\n")
        print("Escolha a sua ação:", end="")
        acao = input()
        print()

        if acao == "1":
            mensagem = input("Digite nome do arquivo txt: ")
            mensagem = u.trata_mensagem(mensagem)

            aux = input("Deseja cifrar utilizando uma label(s/n):")
            if aux == "s":
                label = input("Digite a label:", end="")
                cifra = oaep.RSA_OLAP_enc(chave_publica, mensagem, label)
            elif aux == "n":
                cifra = oaep.RSA_OLAP_enc(chave_publica, mensagem)
            else:
                continue
            if cifra == None:
                continue
            else:
                u.output("cifra_RSA_OAEP.txt", cifra)
                print("arquivo cifrado (cifra_RSA_OAEP.txt)\n")
        
        elif acao == "2":
            cifra = input("Digite nome do arquivo txt: ")
            cifra = u.trata_mensagem(cifra)
            
            aux = input("Deseja decifrar utilizando uma label(s/n):")
            if aux == "s":
                label = input("Digite a label:", end="")
                decifrado = oaep.RSA_OLAP_dec(chave_privada, cifra, label)
            elif aux == "n":
                decifrado = oaep.RSA_OLAP_dec(chave_privada, cifra)
            else:
                continue
            u.output("decifrado_RSA_OAEP.txt", decifrado)
            print("arquivo decifrado (decifrado_RSA_OAEP.txt)\n")
        
        elif acao == "3":
            mensagem = input("Digite nome do arquivo txt: ")
            mensagem = u.trata_mensagem(mensagem)

            mensagem_assinada = av.assinatura(mensagem, chave_privada)

            u.output("arquivo_assinado.txt", mensagem_assinada)
            print("arquivo assinado (arquivo_assinado.txt)\n")

        elif acao == "4":
            arquivo_assinado = input("Digite nome do arquivo assinado txt: ")
            arquivo_assinado = u.trata_mensagem(arquivo_assinado)

            arquivo_original = input("Digite nome do arquivo original txt: ")
            arquivo_original = u.trata_mensagem(arquivo_original)

            if av.verificacao(arquivo_assinado, chave_publica, arquivo_original):
                print("Passou na verificação!\n")
            else:
                print("Não passou na verificação!\n")

        elif acao == "5":
            chave_publica, chave_privada = key.gen_keys()

        elif acao == "6":
            break

        else:
            continue

        input()
    
    print("EXIT")

#with open("teste.txt", "rb") as a:
#    mensagem = a.read()
#
#    chave_publica, chave_privada = key.gen_keys()
#
#    #cifra = oaep.RSA_OLAP_enc(chave_publica, mensagem, "oi tudo bem")
#    #decifra = oaep.RSA_OLAP_dec(chave_privada, cifra, "oi tudo bem")
#    assinatura = av.assinatura(mensagem, chave_privada)
#
#    if av.verificacao(assinatura, chave_publica, mensagem):
#        print("deu certo :)")
#    else:
#        print("deu ruim")
#    print()
#
#    a.close
#


