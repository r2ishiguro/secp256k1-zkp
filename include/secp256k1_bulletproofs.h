#ifndef _SECP256K1_BULLETPROOFS_
# define _SECP256K1_BULLETPROOFS_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/** Opaque data structure that holds the current state of an uncompressed
 * Bulletproof proof generation. This data is not secret and does not need
 * to be handled carefully, but neither does it have any meaning outside
 * of the API functions that use it.
 *
 * Obviously you should not modify it or else you will get invalid proofs.
 *
 * Typical users do not need this structure. If you have more than a few
 * hundred bytes of memory to spare create a proof in one shot with the
 * TODO function instead.
 */
typedef struct {
    unsigned char data[160];
} secp256k1_bulletproofs_prover_context;

/** Opaque structure representing a large number of NUMS generators */
typedef struct secp256k1_bulletproofs_generators secp256k1_bulletproofs_generators;

/** Allocates and initializes a list of NUMS generators
 *  Returns a list of generators, or NULL if allocation failed.
 *  Args:          ctx: pointer to a context object
 *                   n: number of NUMS generators to produce. Should be 128 to allow for
 *                      64-bit rangeproofs
 */
SECP256K1_API secp256k1_bulletproofs_generators *secp256k1_bulletproofs_generators_create(
    const secp256k1_context* ctx,
    size_t n
) SECP256K1_ARG_NONNULL(1);

/** Allocates a list of generators from a static array
 *  Returns a list of generators, or NULL if allocation or parsing failed.
 *  Args:      ctx: pointer to a context object
 *  In:       data: data that came from `secp256k1_bulletproofs_generators_serialize`
 *        data_len: the length of the `data` buffer
 */
SECP256K1_API secp256k1_bulletproofs_generators* secp256k1_bulletproofs_generators_parse(
    const secp256k1_context* ctx,
    const unsigned char* data,
    size_t data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Serializes a list of generators to an array
 *  Returns 1 on success, 0 if the provided array was not large enough
 *  Args:        ctx: pointer to a context object
 *               gen: pointer to the generator set to be serialized
 *  Out:        data: pointer to buffer into which the generators will be serialized
 *  In/Out: data_len: the length of the `data` buffer. Should be initially set to at
 *                    least 33 times the number of generators; will be set to 33 times
 *                    the number of generators on successful return
 */
SECP256K1_API int secp256k1_bulletproofs_generators_serialize(
    const secp256k1_context* ctx,
    const secp256k1_bulletproofs_generators* gen,
    unsigned char* data,
    size_t *data_len
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Destroys a list of NUMS generators, freeing allocated memory
 *  Args:   ctx: pointer to a context object
 *          gen: pointer to the generator set to be destroyed
 *               (can be NULL, in which case this function is a no-op)
 */
SECP256K1_API void secp256k1_bulletproofs_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproofs_generators* gen
) SECP256K1_ARG_NONNULL(1);

# ifdef __cplusplus
}
# endif

#endif
