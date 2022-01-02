from py_ecc.bls import G2ProofOfPossession as bls_pop
import random, os

curve_order = int('52435875175126190479447740508185965837690552500527637822603658699938581184513')

#User1, random secret key.
sk1 = random.randint(1, pow(10,10))
pk1 = bls_pop.SkToPk(sk1)
m = b"ThanhThuy"
sign1 = bls_pop.Sign(sk1, m)
print("Verify user1's single signature", bls_pop.Verify(pk1, m, sign1))

#Attacker create 2 fake public key whose sum = 0
sk2 = random.randint(1, pow(10,10))
sk3 = curve_order - sk2 # = -sk2 % curve_order

pk2 = bls_pop.SkToPk(sk2)
pk3 = bls_pop.SkToPk(sk3)

print("KeyValidate pk2: ",bls_pop.KeyValidate(pk2))
print("KeyValidate pk3: ",bls_pop.KeyValidate(pk3))
print("KeyValidate the aggregate public key pk2 + pk3: ",bls_pop.KeyValidate(bls_pop._AggregatePKs([pk2,pk3]))) #pk2 + pk3 = 0

agg_sign = sign1
m_fake = os.urandom(10)
print("Verify aggregate signature: ", bls_pop.AggregateVerify([pk1,pk2,pk3], [m, m_fake, m_fake], sign1))
