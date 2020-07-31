
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import collections

SecurityLevel = collections.namedtuple('SecurityLevel', ('id', 'preimagebytes', 'crhashbytes'))

# NIST PQC security levels
c1 = SecurityLevel('c1', 16, 32)
c2 = SecurityLevel('c2', 24, 32)
c3 = SecurityLevel('c3', 24, 48)
c4 = SecurityLevel('c4', 32, 48)
c5 = SecurityLevel('c5', 32, 64)

# one hypothetical higher level; note increase to 384-bit secrets, not 320 bits
c6 = SecurityLevel('c6', 48, 64)

# lower levels defined by preimage strength in bits
b80 = SecurityLevel('b80', 10, 20)
b96 = SecurityLevel('b96', 12, 24)
b112 = SecurityLevel('b112', 14, 28)

