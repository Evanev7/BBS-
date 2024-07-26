from random import randint
from functools import reduce

RETRY_LIMIT = 50

#=======================================================================#
#= Can be swapped out with a type-3 bilinear group and it's operations =#
#=======================================================================#

#============  The type-1 bilinear group (p, Zp, Zp, Zp, *) ============#
# Curve order for BLS12_381
p = 52435875175126190479447740508185965837690552500527637822603658699938581184513
# Generators. We're taking G1 = G2 = G12 = Z_p, e(x,y) = (x*y) % p
G1 = 1
G2 = 1

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


# Used to sample random elements from G1.
def totally_secure_cryptographic_hash(n, seed=612789):
    g_n = mult(G1, pow(seed + n + 1,-1,p))
    return g_n

# Simplify a calculation
def pedersen(params, messageList):
    # return G1 + m0 * h0 + m1 * h1 + ...
    return reduce(add, map(mult, params.h, messageList), G1)


class Signature:
    def __init__(self, A,e):
        self.A = A
        self.e = e

class Params:
    def __init__(self, h):
        self.h = h

# Generates public parameters and verifies computation.
class TrustedPublicAuthority:
    @staticmethod
    def GGen(max_messages = 100) -> Params:
        # our totally cryptographically secure hash function ===============================================
        
        h = list(map(totally_secure_cryptographic_hash, range(0, max_messages+2)))
        return Params(h)

    @staticmethod
    def verify(params: Params, public_key: int, signature: Signature, messageList: list[int]) -> int:
        # compute w + e*G2 = (SK+e)*G2
        term_1 = add(public_key, mult(G2,signature.e))

        # Start off A with G1
        term_4 = pedersen(params, messageList)

        return pairing(term_1, signature.A) == pairing(G2, term_4)


class GM:
    def __init__(self, params = TrustedPublicAuthority.GGen(max_messages=100)) -> None:
        self.GKGen()
        self.params = params


    def GKGen(self) -> None:
        self.secret_key = randint(1,p-1) #====================================================================
        self.public_key = mult(G2, self.secret_key)
    
    def gm_sign(self, messageList) -> Signature:
        # C = G1 + m0 * h0 + m1 * h1 + ...
        C = pedersen(self.params, messageList)
        return self.sign(self, C)

    def sign(self, C) -> Signature:
        salt_e, exp_inv = self._generate_invertible_salt()
         
        # A = C * 1/(SK+e)
        A = mult(C, exp_inv)
        # Validation. Failed on py_ecc
        assert(C == mult(A, salt_e + self.secret_key))

        return Signature(A, salt_e) 


    def _generate_invertible_salt(self) -> tuple[int, int]:
        for i in range(RETRY_LIMIT):
            try:
                salt_e = randint(0,p-1)
                exp_inv = pow(salt_e + self.secret_key, -1, p)
                return salt_e, exp_inv
            except ValueError:
                continue
        
        raise ValueError(f"No salt found in {RETRY_LIMIT} attempts.")

class User:
    def __init__(self, params = TrustedPublicAuthority.GGen(max_messages=100)) -> None:
        self.params = params
        self.sig = Signature(0,0)
        
    
    def compute_commitment(self, messageList: list[int]) -> int:
        # C = G1 + m0 * h0 + m1 * h1 + ...
        C = reduce(add, map(mult, self.params.h, messageList), G1)
        return C

    def create_nizk_proof(self, sig:Signature, messageList: list[int], disclosedIndices: list[int]):
        privateMessageList = [messageList[i] for i in range(len(messageList)) if i not in disclosedIndices]
        disclosedMessageList = [messageList[i] for i in disclosedIndices]
        r = randint(1,p-1)
        bar_A = mult(sig.A, r)
        bar_B = mult(add(pedersen(self.params, messageList), mult(sig.A, -sig.e)), r)
        alpha = randint(1,p-1)
        beta = randint(1,p-1)
        delta = [randint(1,p-1) for _ in range(len(privateMessageList))]
        pre_U = add(mult(pedersen(self.params, privateMessageList),alpha),mult(bar_A, beta))
        U = reduce(add, map(mult, self.params.h, delta), pre_U)
        thing = disclosedMessageList
        thing.extend([bar_A, bar_B, U])
        c = totally_secure_cryptographic_hash(reduce(add, thing), seed=238198421)
        s = alpha + r * c
        t = beta - sig.e * c
        u = [delta[i] + r * privateMessageList[i] for i in range(len(delta))]
        return (bar_A, bar_B, c, s, t, u)


class InsecureChannel:
    def __init__(self) -> None:
        self.leaked_data = []


    def user_sign(self, user: User, gm: GM, messageList: list[int]):
        C = user.compute_commitment(messageList)
        sig = gm.sign(C)

        self.leaked_data.append([locals()])
        return sig

    
    def partial_disclosure_proof(self, user: User, gm: GM, messageList: list[int], disclosedIndices: list[int]):
        sig = self.user_sign(user, gm, messageList)
        proof = user.create_nizk_proof(sig, messageList, disclosedIndices)
        disclosedMessageList = [messageList[i] for i in disclosedIndices]
        proof_status = self.check_proof(proof, gm, disclosedMessageList)

        
        self.leaked_data.append([locals()])
        return proof_status
    
    def check_proof(self, proof, gm: GM, disclosedMessageList: list[int]):
        bar_A, bar_B, c, s, t, u = proof
        pre_U = add(add(mult(bar_B, -c), mult(bar_A, t)), mult(pedersen(gm.params, disclosedMessageList), s))
        U = reduce(add, map(mult, gm.params.h, u), pre_U)
        thing = disclosedMessageList
        thing.extend([bar_A, bar_B, U])
        return all([
            pairing(bar_A,  gm.public_key) == pairing(bar_B, G2),
            c == totally_secure_cryptographic_hash(reduce(add, thing), seed=238198421)
        ])



