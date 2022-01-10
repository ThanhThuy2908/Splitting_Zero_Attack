from py_ecc.bls import G2ProofOfPossession as bls
import random, os

curve_order = int('52435875175126190479447740508185965837690552500527637822603658699938581184513')

#User0 and user1 collude with each other, user2 is a normal user
sk0 = random.randint(1, pow(10,10))
sk1 = curve_order - sk0 # = -sk0 % curve_order  #sk0 + sk1 = 0
sk2 = random.randint(1, pow(10,10))

pk0 = bls.SkToPk(sk0)
pk1 = bls.SkToPk(sk1)
pk2 = bls.SkToPk(sk2)

pk01 = bls._AggregatePKs([pk0, pk1])
print("AggregatePk: pk0 + pk1, is valid pubkey", bls._is_valid_pubkey(pk01))
print("KeyValidate pk0 + pk1: ", bls.KeyValidate(bls._AggregatePKs([pk0,pk1])))

blk0 = b"Thanh Thuy"

#The aggregator receives the following signatures
sig0 = bls.Sign(sk0, blk0)
sig1 = bls.Sign(sk1, blk0)
sig2 = bls.Sign(sk2, blk0)
agg_sig = bls.Aggregate([sig0, sig1, sig2])
print("Aggregate Verify 3 signatures: ", bls.AggregateVerify([pk0,pk1,pk2], [blk0,blk0,blk0], agg_sig))
print("Fast Aggregate Verify 3 signatures: ", bls.FastAggregateVerify([pk0, pk1, pk2], blk0, agg_sig))
print("Aggregate Verify sign2: ", bls.AggregateVerify([pk0,pk1,pk2],[blk0,blk0,blk0], sig2))
print("Fast Aggregate Verify sign2: ", bls.FastAggregateVerify([pk0, pk1, pk2], blk0, sig2))

#Now, user0 and user1 send blocks blk1, blk2, blk3 to their neighbors
blk1 = b"Thanh Thuy version 1"
blk2 = b"Thanh Thuy version 2"
blk3 = b"Thanh Thuy version 3"


#All nodes receive only 1 aggregate signature agg_sig from the aggregator, but the accept 3 different blocks blk1, blk2, blk3
print("Aggregate Verify [blk1, blk1, blk0], sig2: ", bls.AggregateVerify([pk0, pk1, pk2], [blk1, blk1, blk0], sig2))
print("Aggregate Verify [blk1, blk1, blk0], agg_sig: ", bls.AggregateVerify([pk0, pk1, pk2], [blk1, blk1, blk0], agg_sig))
print("Aggregate Verify [blk2, blk2, blk0], agg_sig: ", bls.AggregateVerify([pk0, pk1, pk2], [blk2, blk2, blk0], agg_sig))
print("Aggregate Verify [blk3, blk3, blk0], agg_sig: ", bls.AggregateVerify([pk0, pk1, pk2], [blk3, blk3, blk0], agg_sig))

