
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import sys

import pkpsig.keys, pkpsig.signatures

NOISY = True

pkblob, skblob = pkpsig.keys.generate_keypair()

#pkblob = b'\xef`d\xfa\xa4\x9cO\xb9+T\xe7N\x08\x05\xb3\x01,\x845\xb0\xa3\xb4\xb6\x12Uh\xf2G\x1e\xad\x88C\x97\xc1>\x9f\xd3\x89c bOd\x13\x9a"F2l\x018*'
#skblob = b'\xef`d\xfa\xa4\x9cO\xb9+T\xe7N\x08\x05\xb3\x01,\x1a\\\x93tm\xe0\x82\x91\xfb\x9b\xc0tP\x05\xc67\x08\xa8\xafs\x1e\x1b[\xcf5xj\xe5\xd0\xdf)g\x19\x94A\x84d,\x91\xa7:X\xa4\xfa\xd9\x1b=/\xf1\x9a1!\x0bI\x1d>\xb9J\x03\x9bN\xd3\x8fy\xd0QV{\xd6\xc8\x82\\'

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

