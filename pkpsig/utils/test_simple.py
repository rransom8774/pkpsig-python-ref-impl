
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import pkpsig.keys, pkpsig.signatures

#pkblob, skblob = pkpsig.keys.generate_keypair()

pkblob = b'^\x808\xd1_\x19\x94\x95yW\xd7\x9b\xce\xf6\x8a\xfd\xbe9xi\xda\x95\xedd\xeb\xcc\x06\x00R\xce\x14\xe4\x15bf\xd3V\x92\xb3_J0kn\x93\xa1\x87e\xc5\xd6\x9a\x06'
skblob = b'^\x808\xd1_\x19\x94\x95yW\xd7\x9b\xce\xf6\x8a\xfd\xbe\xd0nC\x13Y*L\xa7\xda\xa0\x03\x8b\x8d=\x06\xaa\x9f_m\xdf\x08E_%\x98_\xbc\x88\xf1;\x97\xb4]lt\xd1\x18rvk\xd1\x9d\xa6\x13\xff\x13\xb5\xd1\xf0\xaa.\xec\x9c\x0c\xd8\xc3;\x16\xf2S\x81\x1e\x97\xe4~45d@\xb30\r'

sk = pkpsig.keys.SecretKey().unpack(skblob)
pk = pkpsig.keys.PublicKey().unpack(pkblob)

ivs_sign, ivs_verify = dict(), dict()

signull = pkpsig.signatures.generate_signature(sk, b'', ivs=ivs_sign)
verified = pkpsig.signatures.verify_signature(pk, signull, b'', ivs=ivs_verify)

print('ivs_sign = %r' % ivs_sign)
print('ivs_verify = %r' % ivs_verify)

print('verified = %r' % verified)

