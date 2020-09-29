
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import base64

from . import katgen_rng_sha3
katgen_rng = katgen_rng_sha3

import pkpsig.api, pkpsig.common, pkpsig.params

OUTPUT_BASE_NAME = "PQCsignKAT_%s_%s" % (katgen_rng.RNG_NAME, pkpsig.params.SIGNATURE_NAME)
OUTPUT_REQ_NAME = OUTPUT_BASE_NAME + ".req"
OUTPUT_RSP_NAME = OUTPUT_BASE_NAME + ".rsp"

SEED_BYTES = 48

def b16encode(buf):
    return str(base64.b16encode(buf), 'utf-8')

def run_test(count, seed, msg):
    rv = dict()
    rv['count'] = count
    rv['seed'] = seed
    rv['msg'] = msg
    # init RNG
    saved_randombytes = pkpsig.common.randombytes
    rng = katgen_rng.RNG()
    rng.init(seed)
    pkpsig.common.randombytes = rng.randombytes
    # generate keypair
    pk, sk = pkpsig.api.keypair()
    rv['pk'] = pk
    rv['sk'] = sk
    # generate signature
    sm = pkpsig.api.sign(msg, sk)
    rv['sm'] = sm
    # verify signature
    is_valid, m = pkpsig.api.open(sm, pk)
    # remove RNG
    pkpsig.common.randombytes = saved_randombytes
    # check verification
    assert(is_valid)
    assert(m == msg)
    return rv

def write_test_req(f, count, seed, msg):
    f.write('count = %d\n' % count)
    assert(len(seed) == SEED_BYTES)
    f.write('seed = %s\n' % b16encode(seed))
    f.write('mlen = %d\n' % len(msg))
    f.write('msg = %s\n' % b16encode(msg))
    f.write('pk =\nsk =\nsmlen =\nsm =\n\n')
    pass

def write_test_rsp(f, results):
    f.write('count = %d\n' % results['count'])
    seed = results['seed']
    assert(len(seed) == SEED_BYTES)
    f.write('seed = %s\n' % b16encode(seed))
    msg = results['msg']
    f.write('mlen = %d\n' % len(msg))
    f.write('msg = %s\n' % b16encode(msg))
    pk = results['pk']
    assert(len(pk) == pkpsig.params.BYTES_PUBLICKEY)
    f.write('pk = %s\n' % b16encode(pk))
    sk = results['sk']
    assert(len(sk) == pkpsig.params.BYTES_SECRETKEY)
    f.write('sk = %s\n' % b16encode(sk))
    sm = results['sm']
    f.write('smlen = %d\n' % len(sm))
    f.write('sm = %s\n\n' % b16encode(sm))
    pass

def generate_test_reqs():
    rng = katgen_rng.RNG()
    rng.init(bytes(range(SEED_BYTES)))
    reqs = list()
    for count in range(100):
        seed = rng.randombytes(SEED_BYTES)
        mlen = 33*(count+1)
        msg = rng.randombytes(mlen)
        reqs.append((count, seed, msg))
        pass
    return reqs

def generate_test_rsps(reqs):
    rsps = list()
    for req in reqs:
        count, seed, msg = req
        if count % 10 == 0:
            print(count)
            pass
        rsps.append(run_test(count, seed, msg))
        pass
    return rsps

def main():
    reqs = generate_test_reqs()
    rsps = generate_test_rsps(reqs)
    with open(OUTPUT_REQ_NAME, 'wt') as f_req:
        for req in reqs:
            count, seed, msg = req
            write_test_req(f_req, count, seed, msg)
            pass
        pass
    with open(OUTPUT_RSP_NAME, 'wt') as f_rsp:
        for rsp in rsps:
            write_test_rsp(f_rsp, rsp)
            pass
        pass
    pass

if __name__ == "__main__":
    main()
    pass

