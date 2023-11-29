import random

#gera uma chave pública e uma privada, ambas aleatórias (pub_key, pri_key) = ((n, e), (n, d))
def gen_keys():
    print("gerando primeiro primo...")
    p = random_prime()
    print("primeiro primo criado!")
    
    print("gerando segundo primo...")
    q = random_prime()
    print("segundo primo criado!")
    
    n = p * q
    aux = (p - 1)*(q - 1)

    e = 0
    for i in range(4, n - 1):
        if mdc(i, aux) == 1:
            e = i
            break
    
    d = ext_algoritmo_euclides(e, aux)[0] #e*d + aux*y = 1 => e*d == 1 (mod aux)

    i = 1
    while d < 0:
        di = d + aux*i
        if di > 0:
            d = di
            break
        i += 1

    print("chaves criadas!")
    return ((n, e), (n, d))


#acha os valores x, y tal que a*x + b*y = mdc(a, b)
def ext_algoritmo_euclides(a, b):
    old_r, r = (a, b)
    old_s, s = (1, 0)
    old_t, t = (0, 1)
    
    while r != 0:
        quociente = old_r // r
        
        aux = r
        r = old_r - (quociente * aux)
        old_r = aux
        
        aux = s
        s = old_s - (quociente * aux)
        old_s = aux
        
        aux = t
        t = old_t - (quociente * aux)
        old_t = aux
    
    return (old_s, old_t)

#retorna um provável primo aleatório de 1024 bits 
def random_prime():
    achou = False
    while True:
        i = random.getrandbits(1024)

        if is_prime(i):
            return i
        
#testa se n é provavelente é primo ou com certeza não é (Miller-Rabin)
def is_prime(n, k=6):

    if n == 2:
        return True
    
    if n % 2 == 0:
        return False
    
    s = 0
    while True:
        if (n - 1) % (2**(s+1)) == 0:
            s += 1
        else:
            break

    d = (n - 1) // (2**s)
    
    for _ in range(k):
        
        a = random.randint(2, n - 2)
        if mdc(n, a) != 1:
            return False

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        achou = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                achou = True
                break
        if achou:
            continue
        else:
            return False
    
    return True    

#retorna o mdc entre a e b
def mdc(a, b):
    
    resto = a % b
    if resto == 0:
        return b
    else:
        return mdc(b, resto)
