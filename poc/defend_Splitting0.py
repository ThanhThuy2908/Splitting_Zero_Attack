from py_ecc.bls import G2ProofOfPossession as bls_pop
import random, os
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls import G2Basic as bls_basic

from py_ecc.bls.hash import i2osp, os2ip
from py_ecc.bls.g2_primatives import *
from py_ecc.optimized_bls12_381.optimized_curve import *

curve_order = int('52435875175126190479447740508185965837690552500527637822603658699938581184513')

#User3, random secret key.
sk3 = random.randint(1, pow(10,10))
pk3 = bls_pop.SkToPk(sk3)
m = b"ThanhThuy"
sign3 = bls_pop.Sign(sk3, m)
print("Verify user1's single signature", bls_pop.Verify(pk3, m, sign3))

#Attacker create 2 fake public key whose sum = 0
sk1 = random.randint(1, pow(10,10))
sk2 = curve_order - sk1 # = -sk1 % curve_order

pk1 = bls_pop.SkToPk(sk1)
pk2 = bls_pop.SkToPk(sk2)

print("KeyValidate pk1: ",bls_pop.KeyValidate(pk1))
print("KeyValidate pk2: ",bls_pop.KeyValidate(pk2))
print("KeyValidate the aggregate public key pk1 + pk2: ",bls_pop.KeyValidate(bls_pop._AggregatePKs([pk1,pk2]))) #pk1 + pk2 = 0

m_fake = os.urandom(10)
agg_sign = bls_pop.Aggregate([sign3, bls_pop.Sign(sk1, m_fake), bls_pop.Sign(sk2, m_fake)])  #agg_sig = sign1 + sign2 + sign 3
print("Verify aggregate signature (agg_sig):", bls_pop.AggregateVerify([pk1,pk2,pk3], [m_fake, m_fake, m], agg_sign))
print("Verify aggregate signature (sig3): ", bls_pop.AggregateVerify([pk1,pk2,pk3], [m_fake, m_fake, m], sign3))

print("Thuy_AggregateVerify against splitting zero attack: ",bls_pop.Thuy_AggregateVerify([pk1, pk2, pk3], [m_fake, m_fake, m], agg_sign))
print("Thuy_FastAggregateVerify against splitting zero attack: ",bls_pop.Thuy_FastAggregateVerify([pk1, pk2, pk3], [m_fake, m_fake, m], agg_sign))
