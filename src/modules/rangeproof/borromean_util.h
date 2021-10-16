/**********************************************************************
 * Copyright (c) 2021 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_BORROMEAN_UTIL_H_
#define _SECP256K1_BORROMEAN_UTIL_H_

#include <stddef.h> /* for size_t */
#include <stdint.h> /* for uint64_t */

#include "scalar.h"

/** A pointer to a function that returns a size_t given a ring index
 *
 * Used by borromean_sign to look up the size of each ring and the secret
 * index, to avoid caching these values which would take excessive stack.
 * As it turns out, both these values can be determined from the mantissa (for
 * rangeproofs) or are constant (for surjection proofs or ring signatures)
 *
 * In:  input: a single closed-over value
 *      index: which ring in the borromean ring signature this lookup
 *             function should look up
 */
typedef struct secp256k1_borromean_sz_closure {
    uint64_t input;
    size_t (*call)(const struct secp256k1_borromean_sz_closure* self, size_t index);
} secp256k1_borromean_sz_closure;

/** Create a sz_closure that just returns a constant */
secp256k1_borromean_sz_closure secp256k1_borromean_sz_closure_const(uint64_t c);

/** A pointer to a function that returns a scalar given an index
 *
 * Used by borromean_sign and borromean_verify to obtain s-values from a
 * serialized proof. Used in essentially the same way by both rangeproofs
 * and surjection proofs, which both contain a big consecutive blob of
 * scalar values. Scalar-indexed, not byte-indexed.a
 *
 * This closure does no bounds-checking and should never be used with
 * untrusted input.
 *
 * Out:  scalar: scalar which is parsed out of the serialized data
 * In:     data: scalar-containing part of the serialized proof
 *        index: which scalar to look up
 *
 * Returns 1 on success, 0 on failure (overflow or zero output)
 */
typedef struct secp256k1_borromean_sc_closure {
    const unsigned char* data;
    int (*call)(const struct secp256k1_borromean_sc_closure* self, secp256k1_scalar* out, size_t index);
} secp256k1_borromean_sc_closure;

/** Create a sc_closure that indexes into a blob of scalar data */
secp256k1_borromean_sc_closure secp256k1_borromean_sc_closure_blob(const unsigned char* blob);

#endif
