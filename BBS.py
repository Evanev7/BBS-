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
class Params:
    def __init__(self, g, h, u):
        self.g = g
        self.h = h
        self.u = u

class TrustedPublicAuthority:
    @staticmethod
    def GSetup(max_messages = 100) -> Params:
        # our totally cryptographically secure hash function ===============================================
        g = list(map(totally_secure_cryptographic_hash_1, range(0, max_messages+2)))
        h = list(map(totally_secure_cryptographic_hash_2, range(0, max_messages+2)))
        u = list(map(totally_secure_cryptographic_hash_3, range(0, max_messages+2)))
        return Params(g, h, u)


class GM:
    def __init__(self, params = TrustedPublicAuthority.GSetup(max_messages=100)) -> None:
        self.Reg = []
        self.GKGen()
        self.g = params.g
        self.h = params.h
        self.u = params.u


    def GKGen(self) -> None:
        self.secret_key = randint(0,p-1) #====================================================================
        self.public_key = mult(G2, self.secret_key)
    
    
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


    def _write(self, entry, mpk) -> None:
        self.Reg.append((len(self.Reg), entry, mpk))

    def _generate_invertible_salt(self) -> tuple[int, int]:
        for i in range(RETRY_LIMIT):
            salt_e = randint(0,p-1)
            exp_inv = pow(salt_e + self.secret_key, -1, p)
            return salt_e, exp_inv
        raise ValueError(f"No salt found in {RETRY_LIMIT} attempts.")


    def join_1(self) -> int:
        return len(self.Reg)
    
    def join_2(self, Cprime, proof) -> int:
        #if verify(proof):
        self.tempCprime = Cprime
        self.tempsprimeprime = randint(0, p-1)
        return self.tempsprimeprime

    def join_3(self, entry, proof) -> int:
        # if verify(proof):
        C = self.tempCprime + self.tempsprimeprime * self.g[1]
        salt_e, exp_inv = self._generate_invertible_salt()
        A = exp_inv * (self.g[0] + C)

        self._write(entry, salt_e)
        return (A, salt_e, self.tempsprimeprime) 

class User:
    def __init__(self, params = TrustedPublicAuthority.GSetup(max_messages=100)) -> None:
        self.params = params
        
    
    def join_1(self, id: int) -> tuple:
        self.id = id
        self.sprime = randint(0, p-1)
        self.t = randint(0, p-1)
        self.x = randint(0, p-1)
        Cprime = self.sprime * self.params.g[1] + self.t * self.params.g[2] + self.x * self.params.g[3]
        proof = 0 #======================================================================================
        return Cprime, proof
    
    def join_2(self, sprimeprime: int) -> tuple:
        self.s = self.sprime + sprimeprime
        entry = (self.id, self.x * self.params.u[0])
        proof = 0 #======================================================================================
        return entry, proof

    def join_3(self, A: int, e: int, sprimeprime: int, gm: GM): #GM here for public parameters.
        term_3 = self.params.g[0] + self.s * self.params.g[1] + self.t * self.params.g[2] + self.x * self.params.g[3]
        if pairing(A, gm.public_key + e * G2) != pairing(term_3, G2):
            raise ValueError("Invalid personal signature received.")
        self.public_key = e
        self.private_key = (A,self.s,self.t,self.x)


class InsecureChannel:
    def __init__(self) -> None:
        self.leaked_data = []


    def join(self, gm: GM, user: User):
        user_id = gm.join_1()
        Cprime, proof = user.join_1(user_id)
        sprimeprime = gm.join_2(Cprime, proof)
        entry, proof_2 = user.join_2(sprimeprime)
        (A,salt_e, sprimeprime) = gm.join_3(entry, proof_2)
        user.join_3(A, salt_e, sprimeprime, gm)

        self.leaked_data.append([locals()])

