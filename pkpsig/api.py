
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

from . import keys, params, signatures

def keypair():
    pk, sk = keys.generate_keypair()
    return (pk, sk)

def sign(m, sk):
    skobj = keys.SecretKey().unpack(sk)
    sig = signatures.generate_signature(skobj, m)
    assert(len(sig) == params.BYTES_SIGNATURE)
    sm = sig + m
    return sm

def open(sm, pk):
    pkobj = keys.PublicKey().unpack(pk)
    sig, m = sm[:params.BYTES_SIGNATURE], sm[params.BYTES_SIGNATURE:]
    is_valid = signatures.verify_signature(pkobj, sig, m)
    if is_valid:
        return (True, m)
    else:
        return (False, None)
    pass

