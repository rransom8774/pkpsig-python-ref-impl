
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import pkpsig.keys, pkpsig.signatures

#pkblob, skblob = pkpsig.keys.generate_keypair()

pkblob = b'\xef`d\xfa\xa4\x9cO\xb9+T\xe7N\x08\x05\xb3\x01,\x845\xb0\xa3\xb4\xb6\x12Uh\xf2G\x1e\xad\x88C\x97\xc1>\x9f\xd3\x89c bOd\x13\x9a"F2l\x018*'
skblob = b'\xef`d\xfa\xa4\x9cO\xb9+T\xe7N\x08\x05\xb3\x01,\x1a\\\x93tm\xe0\x82\x91\xfb\x9b\xc0tP\x05\xc67\x08\xa8\xafs\x1e\x1b[\xcf5xj\xe5\xd0\xdf)g\x19\x94A\x84d,\x91\xa7:X\xa4\xfa\xd9\x1b=/\xf1\x9a1!\x0bI\x1d>\xb9J\x03\x9bN\xd3\x8fy\xd0QV{\xd6\xc8\x82\\'

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

ivs_sign, ivs_verify = dict(), dict()

signull = pkpsig.signatures.generate_signature(sk, b'', ivs=ivs_sign)
verified = pkpsig.signatures.verify_signature(pk, signull, b'', ivs=ivs_verify)

print('ivs_sign = %r' % ivs_sign)
print('ivs_verify = %r' % ivs_verify)

print('verified = %r' % verified)

