from py_ecc.bls import G2ProofOfPossession as bls_pop
import random, os

curve_order = int('52435875175126190479447740508185965837690552500527637822603658699938581184513')

#Attacker create 2 fake public key whose sum = 0
sk1 = random.randint(1, pow(10,10))
sk2 = curve_order - sk1 # = -sk2 % curve_order

pk1 = bls_pop.SkToPk(sk1)
pk2 = bls_pop.SkToPk(sk2)

m = b"Thanh Thuy"

sig1 = bls_pop.Sign(sk1, m)
sig2 = bls_pop.Sign(sk2, m)
agg_sig = bls_pop.Aggregate([sig1, sig2])

print("FastAggregateVerify: ", bls_pop.FastAggregateVerify([pk1, pk2], m, agg_sig))
print("AggregateVerify: ", bls_pop.AggregateVerify([pk1, pk2], [m,m], agg_sig))

