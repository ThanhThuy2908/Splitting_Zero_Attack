from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls import G2Basic as bls_basic

from py_ecc.bls.hash import i2osp, os2ip
from py_ecc.bls.g2_primatives import *
from py_ecc.optimized_bls12_381.optimized_curve import *

sk0 = 1234
sk1 = 1111
sk2 = 2222
sk3 = 3333
sk4 = 4444
pk1 = bls.SkToPk(sk1)
pk2 = bls.SkToPk(sk2)
pk3 = bls.SkToPk(sk3)
pk4 = bls.SkToPk(sk4)

#==================Equivalent interfaces return different verification results===================
#We intentionally choose P as valid signature so that it stays in a correct subgroup
msg0 = b"message"
sig0 = bls.Sign(sk0, msg0)
P = signature_to_G2(sig0)

print("\\nConsensus attack against proff of possession  ")
msg1 = b"message 0"
msg2 = b"message 0"
msg3 = b"message 1"
msg4 = b"message 1"
sig1 = bls.Sign(sk1, msg1)
sig2 = bls.Sign(sk2, msg2)
sig3 = bls.Sign(sk3, msg3)
sig4 = bls.Sign(sk4, msg4)

#The attacker creates the following signatures
#sig1 - 2P
sig1_prime = G2_to_signature(add(signature_to_G2(sig1), neg(multiply(P, 2))))
#sig2 + P
sig2_prime = G2_to_signature(add(signature_to_G2(sig2), P))
#sig3 - P
sig3_prime = G2_to_signature(add(signature_to_G2(sig3), neg(P)))
#sig4 + 2P
sig4_prime = G2_to_signature(add(signature_to_G2(sig4), multiply(P, 2)))

print("subgroup check sig1_prime: ", subgroup_check(signature_to_G2(sig1_prime)))
print("subgroup check sig2_prime: ", subgroup_check(signature_to_G2(sig2_prime)))
print("subgroup check sig3_prime: ", subgroup_check(signature_to_G2(sig3_prime)))
print("subgroup check sig4_prime: ", subgroup_check(signature_to_G2(sig4_prime)))

sig1234_prime = bls.Aggregate([sig1_prime, sig2_prime, sig3_prime, sig4_prime])

print("User1 aggregate verify 4 messages: ", bls.AggregateVerify([pk1, pk2, pk3, pk4], [msg1, msg2, msg3, msg4], sig1234_prime))

sig12_prime = bls.Aggregate([sig1_prime, sig2_prime])
sig34_prime = bls.Aggregate([sig3_prime, sig4_prime])
pk12 = bls._AggregatePKs([pk1, pk2])
pk34 = bls._AggregatePKs([pk3,pk4])
print("User2 fast aggregate verify the first 2 messages and the last 2 messages. They all return false so user2 discards sig12_prime, sig34_prime: ", bls.FastAggregateVerify([pk1, pk2], msg1, sig12_prime), bls.FastAggregateVerify([pk3,pk4], msg3, sig34_prime))

print("User2 never executes the this last step because sig12_prime and sig34_primt are invalid: ", bls.AggregateVerify([pk12, pk34], [msg1, msg3], bls.Aggregate([sig12_prime, sig34_prime])))

print("Mathematically we expect both sides return the same result, but they do not: ", bls.AggregateVerify([pk1, pk2, pk3, pk4], [msg1, msg2, msg3, msg4], sig1234_prime), bls.FastAggregateVerify([pk1, pk2], msg1, sig12_prime) and bls.FastAggregateVerify([pk3, pk4], msg3, sig34_prime) and bls.AggregateVerify([pk12, pk34], [msg1, msg3], bls.Aggregate([sig12_prime, sig34_prime])))

#======================FastAggregateVerify's aggregation order leads to different verification results
m = b"message"
sig1 = bls.Sign(sk1, m)
sig2 = bls.Sign(sk2, m)
sig3 = bls.Sign(sk3, m)

#The attacker creates the following modified signatures
#sig1 - 2P
sig1_prime = G2_to_signature(add(signature_to_G2(sig1), neg(multiply(P, 2))))
#sig2 - P
sig2_prime = G2_to_signature(add(signature_to_G2(sig2), neg(P)))
#sig3 + 3P
sig3_prime = G2_to_signature(add(signature_to_G2(sig3), multiply(P, 3)))

print(bls.FastAggregateVerify([pk1, pk2, pk3], m, bls.Aggregate([sig1_prime, sig2_prime, sig3_prime])))
sig12_prime = bls_basic.Aggregate([sig1_prime, sig2_prime])
print(bls.FastAggregateVerify([pk1, pk2], m, sig12_prime))
print(bls.FastAggregateVerify([pk12, pk3], m, bls.Aggregate([sig12_prime, sig3_prime])))