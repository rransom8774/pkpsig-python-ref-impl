
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import sys

import pkpsig.keys, pkpsig.signatures

NOISY = True

pkblob, skblob = pkpsig.keys.generate_keypair()

#pkblob = b'^\x808\xd1_\x19\x94\x95yW\xd7\x9b\xce\xf6\x8a\xfd\xbe9xi\xda\x95\xedd\xeb\xcc\x06\x00R\xce\x14\xe4\x15bf\xd3V\x92\xb3_J0kn\x93\xa1\x87e\xc5\xd6\x9a\x06'
#skblob = b'^\x808\xd1_\x19\x94\x95yW\xd7\x9b\xce\xf6\x8a\xfd\xbe\xd0nC\x13Y*L\xa7\xda\xa0\x03\x8b\x8d=\x06\xaa\x9f_m\xdf\x08E_%\x98_\xbc\x88\xf1;\x97\xb4]lt\xd1\x18rvk\xd1\x9d\xa6\x13\xff\x13\xb5\xd1\xf0\xaa.\xec\x9c\x0c\xd8\xc3;\x16\xf2S\x81\x1e\x97\xe4~45d@\xb30\r'

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

def frob_byte(sig, bytepos):
    buf = bytearray(sig)
    buf[bytepos] = (buf[bytepos] + 1) % 256
    return bytes(buf)

exceptions = dict()

def verify_noexcept(pk, sig, msg):
    try:
        return pkpsig.signatures.verify_signature(pk, sig, msg)
    except:
        ei = sys.exc_info()
        exceptions[(pk, sig, msg)] = ei
        print('Exception %r' % ei[0])
        return False
    assert(not "can't happen")
    pass

bogons = dict()

def report(testname, testsub, result, expected):
    if result != expected:
        bogons[(testname, testsub)] = (result, expected)
        pass
    if NOISY or (result != expected):
        print('  %s: %r (expected %r)' % (testsub, result, expected))
        pass
    pass

def test_loop(testname, pk, sig, msg, is_valid):
    print('%s:' % testname)
    report(testname, 'unmodified', verify_noexcept(pk, sig, msg), is_valid)
    for i in range(len(sig)):
        frobbed = frob_byte(sig, i)
        report(testname, 'frobbed byte %d' % i, verify_noexcept(pk, frobbed, msg), False)
        pass
    pass

signull = pkpsig.signatures.generate_signature(sk, b'')
sigalpha = pkpsig.signatures.generate_signature(sk, b'abcdefghijklmnopqrstuvwxyz')

test_loop('null message', pk, signull, b'', True)
test_loop('lowercase-alphabet message', pk, sigalpha, b'abcdefghijklmnopqrstuvwxyz', True)

test_loop('null-message sig verified for lowercase-alphabet message', pk, signull, b'abcdefghijklmnopqrstuvwxyz', False)
test_loop('lowercase-alphabet message sig verified for null message', pk, sigalpha, b'', False)

print('exceptions = %r' % exceptions)
print('bogons = %r' % bogons)

