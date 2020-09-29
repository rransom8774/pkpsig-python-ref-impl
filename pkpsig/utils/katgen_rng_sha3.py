
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import hashlib

RNG_NAME = 'SHA3'
STATE_BYTES = 64

class RNG(object):
    __slots__ = ('state',)
    def init(self, seed):
        self.state = hashlib.shake_256(seed).digest(STATE_BYTES)
        pass
    def randombytes(self, nbytes):
        buf = hashlib.shake_256(self.state).digest(nbytes + STATE_BYTES)
        rv = buf[:nbytes]
        self.state = buf[nbytes:]
        return rv
    pass

