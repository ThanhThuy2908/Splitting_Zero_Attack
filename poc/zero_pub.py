import os
from py_ecc.bls import G2ProofOfPossession as bls_pop
#Random message
message = os.urandom(39)
#Zero public key
pub =  b"@"+ b"\x00" * 47
#Zero signature
sig = b"@"  + b"\x00" * 95

print(bls_pop._is_valid_pubkey(pub))
print("KeyValidate:" ,bls_pop.KeyValidate(pub))
print("Verify: ",bls_pop.Verify(pub, message, sig))


# ===================================



