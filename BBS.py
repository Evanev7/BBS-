from random import randint

RETRY_LIMIT = 50
# Curve order for BLS12_381
p = 52435875175126190479447740508185965837690552500527637822603658699938581184513
# Generators. We're taking G1 = G2 = G12 = Z_p, e(x,y) = (x*y) % p
G1 = 1
G2 = 1
G12 = 1

def mult(a,b):
    return (a*b) % p
def add(a,b):
    return (a+b) % p
def pairing(a,b):
    return (a*b) % p


# This should work, but optimized_bls12_381 doesn't compute correctly, and bls12_381 doesn't compute pairings efficiently enough to be useful.
# from py_ecc import bls12_381 as cv
# G1 = cv.G1
# G2 = cv.G2
# G12 = cv.G12
# mult = cv.multiply
# add = cv.add
# pairing = cv.pairing
# p = cv.curve_order



def totally_secure_cryptographic_hash_1(n):
    seed = 612789
    g_n = mult(G1, pow(seed + n + 1,-1,p))

    return g_n


def totally_secure_cryptographic_hash_2(n):
    seed = 41527809
    g_n = mult(G2, pow(seed + n + 1,-1,p))

    return g_n

def totally_secure_cryptographic_hash_3(n):
    seed = 2160421
    g_n = mult(G2, pow(seed + n + 1,-1,p))
    return g_n

class Signature:
    def __init__(self, A,e,s):
        self.A = A
        self.e = e
        self.s = s


class TrustedPublicAuthority:
    def GSetup(self, max_messages = 100) -> None:
        seed = 91597
        # our totally cryptographically secure hash function ===============================================
        self.g = list(map(totally_secure_cryptographic_hash_1, range(seed, max_messages+2+seed)))
        self.h = list(map(totally_secure_cryptographic_hash_2, range(seed, max_messages+2+seed)))
        self.u = list(map(totally_secure_cryptographic_hash_3, range(seed, max_messages+2+seed)))
    
    GSetup()



class GM:
    def __init__(self, max_messages = 10) -> None:
        Reg = []
        self.GKGen()
        
        self.g = TrustedPublicAuthority.g
        self.h = TrustedPublicAuthority.h
        self.u = TrustedPublicAuthority.u


    def GKGen(self) -> None:
        self.secret_key = randint(0,p) #====================================================================
        self.public_key = mult(G2, self.secret_key)
    
    def Join(self, user: User):
        pass
    
    def sign(self, messageList: list[int]) -> Signature:
        salt_s = randint(0, p-1)
        for i in range(RETRY_LIMIT):
            try:
                salt_e = randint(0, p-1) # could be hash
                exp_inv = pow(salt_e + self.secret_key, -1, p)
                break
            except ValueError:
                continue
        
        # Start off A with G1+s*g0
        progress_A = add(G1, mult(self.g[0], salt_s)) 
        for i, message in enumerate(messageList):
            # then multiply by m1*g1+m2*g2 etc.
            progress_A = add(progress_A, mult(self.g[i+1], message)) 
        A = mult(progress_A, exp_inv)
        assert(progress_A == mult(A, salt_e + self.secret_key))

        return Signature(A, salt_e, salt_s) 


    def verify(self, signature: Signature, messageList: list[int]) -> int:
        # compute w + e*G2 = (SK+e)*G2
        term_1 = add(self.public_key, mult(G2,signature.e))

        # Start off A with G1+s*g0
        term_4 = add(G1, mult(self.g[0], signature.s))
        for i, message in enumerate(messageList): 
            # then multiply by m1*g1+m2*g2 etc.
            term_4 = add(term_4, mult(self.g[i+1], message))

        return pairing(term_1, signature.A) == pairing(G2, term_4)


    def write(self, entry, mpk) -> None:
        self.Reg.append((self.Reg.length(), entry, mpk))

class User:
    def __init__(self) -> None:
        self


class InsecureChannel:
    def __init__(self) -> None:
        pass


    def join(gm: GM, user: User):
        pass