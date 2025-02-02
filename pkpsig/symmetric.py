
# Authors: Robert Ransom

# This software is released to the public domain.

# To the extent permitted by law, this software is provided WITHOUT ANY
# WARRANTY WHATSOEVER.

import struct
import hashlib

from . import consts, params, permops

struct_ui8 = struct.Struct('<B')
struct_ui16 = struct.Struct('<H')
struct_ui32 = struct.Struct('<I')

def pack_ui8(x):
    return struct_ui8.pack(x)
def pack_ui8_vec(x):
    return b''.join(struct_ui8.pack(el) for el in x)
def unpack_ui8_vec(x):
    return [el[0] for el in struct_ui8.iter_unpack(x)]

def pack_ui16(x):
    return struct_ui16.pack(x)
def pack_ui16_vec(x):
    return b''.join(struct_ui16.pack(el) for el in x)
def unpack_ui16_vec(x):
    return [el[0] for el in struct_ui16.iter_unpack(x)]

def pack_ui32(x):
    return struct_ui32.pack(x)
def unpack_ui32_vec(x):
    return [el[0] for el in struct_ui32.iter_unpack(x)]

def hash_init(context, prefix = None):
    hobj = hashlib.shake_256()
    hobj.update(pack_ui8(context))
    if prefix is not None:
        hobj.update(prefix)
        pass
    return hobj

def hash_expand_index_seed(hobj_, index, seed, outbytes):
    hobj = hobj_.copy()
    hobj.update(pack_ui32(index))
    hobj.update(seed)
    return hobj.digest(outbytes)

def hash_expand_index(hobj_, index, outbytes):
    return hash_expand_index_seed(hobj_, index, b'', outbytes)

def hash_expand_index_seed_to_perm(hobj_, index, seed, outlen, check_uniform = False):
    buf = unpack_ui32_vec(hash_expand_index_seed(hobj_, index, seed, outlen*4))
    assert(len(buf) == outlen)
    assert(outlen <= 128) # magic number and protocol constant
    for i in range(outlen):
        buf[i] = buf[i] & 0xFFFFFF80
        buf[i] = buf[i] | i
        pass
    buf.sort()
    if check_uniform:
        for i in range(outlen - 1):
            if (buf[i] & 0xFFFFFF80) == (buf[i+1] & 0xFFFFFF80):
                return None
            pass
        pass
    for i in range(outlen):
        buf[i] = buf[i] & 0x7F
        pass
    return buf

def hash_expand_index_to_perm(hobj_, index, outlen, check_uniform = False):
   return hash_expand_index_seed_to_perm(hobj_, index, b'', outlen, check_uniform = False)

def hash_expand_index_seed_to_fqvec(hobj_, index, seed, outlen, check_uniform = False):
    buf = unpack_ui32_vec(hash_expand_index_seed(hobj_, index, seed, outlen*4))
    assert(len(buf) == outlen)
    if check_uniform:
        CEILING = 0x100000000 - (0x100000000 % params.PKP_Q)
        for i in range(outlen):
            if buf[i] >= CEILING:
                return None
            pass
        pass
    for i in range(outlen):
        buf[i] = buf[i] % params.PKP_Q
        pass
    return buf

def hash_expand_index_to_fqvec(hobj_, index, outlen, check_uniform = False):
   return hash_expand_index_seed_to_fqvec(hobj_, index, b'', outlen, check_uniform = False)

def hash_expand_suffix(hobj_, suffix, outbytes):
    hobj = hobj_.copy()
    hobj.update(suffix)
    return hobj.digest(outbytes)

def hash_expand_suffix_to_fqvec(hobj_, suffix, outlen, check_uniform = False):
    buf = unpack_ui32_vec(hash_expand_suffix(hobj_, suffix, outlen*4))
    assert(len(buf) == outlen)
    if check_uniform:
        CEILING = 0x100000000 - (0x100000000 % params.PKP_Q)
        for i in range(outlen):
            if buf[i] >= CEILING:
                return None
            pass
        pass
    for i in range(outlen):
        buf[i] = buf[i] % params.PKP_Q
        pass
    return buf

def hash_expand_suffix_to_fwv_nonuniform(hobj_, suffix, outlen, weight):
    buf = unpack_ui32_vec(hash_expand_suffix(hobj_, suffix, outlen*4))
    assert(len(buf) == outlen)
    for i in range(outlen):
        buf[i] = buf[i] & 0xFFFFFFFE
        if i < weight:
            buf[i] = buf[i] | 1
            pass
        pass
    buf.sort()
    for i in range(outlen):
        buf[i] = buf[i] & 1
        pass
    return buf

def hash_digest_suffix(hobj_, suffix, outbytes):
    hobj = hobj_.copy()
    hobj.update(suffix)
    return hobj.digest(outbytes)

def hash_digest(hobj_, outbytes):
    return hash_digest_suffix(hobj_, b'', outbytes)

def fqvec_to_hash_input(vec):
    assert(params.PKP_Q <= 0xFFFF)
    for i in range(len(vec)):
        assert(vec[i] >= 0)
        assert(vec[i] <= params.PKP_Q)
        pass
    return pack_ui16_vec(vec)

def hash_digest_suffix_fqvec(hobj_, suffixvec, outbytes):
    return hash_digest_suffix(hobj_, fqvec_to_hash_input(suffixvec), outbytes)

def perm_to_hash_input(perm):
    assert(params.PKP_N <= 0xFF)
    assert(len(perm) == params.PKP_N)
    permops.check_perm(perm, perm)
    return pack_ui8_vec(perm)

def hash_digest_index_perm_fqvec(hobj_, index, suffixperm, suffixvec, outbytes):
    return hash_digest_suffix(hobj_, pack_ui32(index) +
                              perm_to_hash_input(suffixperm) +
                              fqvec_to_hash_input(suffixvec), outbytes)

def hash_digest_index_suffix(hobj_, index, suffix, outbytes):
    return hash_digest_suffix(hobj_, pack_ui32(index) + suffix, outbytes)

def tree_hash_level(hobj_, first_index, params, nodes, nodebytes, degree):
    dest = list()
    hash_index, node_index = first_index, 0
    while node_index < len(nodes):
        # Python notation for [nodes[node_index], nodes[node_index+1], ..., nodes[node_index+degree - 1] ]
        # upper bound is silently clamped to len(nodes)
        innodes = nodes[node_index:node_index+degree]
        dest.append(hash_digest_index_suffix(hobj_,
                                             hash_index,
                                             params + b''.join(innodes),
                                             nodebytes))
        hash_index += 1
        node_index += degree
        pass
    return (hash_index, dest)

def tree_hash(context, prefix, params, leaves, prehash_leaves, nodebytes, degree, outbytes):
    hobj = hash_init(context, prefix)
    # First, hash each leaf node down to a nodebytes-bytes digest if requested
    if prehash_leaves:
        nodes = [hash_digest_index_suffix(hobj, i, params + leaves[i], nodebytes)
                 for i in range(len(leaves))]
        next_index = len(leaves)
        pass
    else:
        nodes = leaves
        next_index = 0
        pass
    # Then, hash nodes together until there is only one left
    while len(nodes) > 1:
        next_index, nodes = tree_hash_level(hobj, next_index, params, nodes, nodebytes, degree)
        pass
    assert(nodebytes >= outbytes)
    return nodes[0][:outbytes]

def tree_hash_sorting(context, prefix, params, indexed_leaves, prehash_leaves, nodebytes, degree, outbytes):
    """
    External API for tree hashing.  May allow a slightly faster implementation
    with some tree-hash functions than fully sorting the leaves by index first.
    """
    ilsorted = list(indexed_leaves)
    ilsorted.sort()
    leaves = list()
    for i in range(len(indexed_leaves)):
        assert(ilsorted[i][0] == i)
        leaves.append(ilsorted[i][1])
        pass
    return tree_hash(context, prefix, params, leaves, prehash_leaves, nodebytes, degree, outbytes)

def generate_msghash_salt(sk, message):
    # in the symmetric module because for narrow-pipe hash functions,
    # saltgenseed should precede the message
    hobj = hash_init(consts.HASHCTX_INTERNAL_GENMSGHASHSALT)
    return hash_digest_suffix(hobj,
                              message + sk.saltgenseed,
                              params.PKPSIG_BYTES_MSGHASHSALT)

