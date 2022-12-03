/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_MAIN_
#define _SECP256K1_MODULE_BULLETPROOFS_MAIN_

#include "include/secp256k1_bulletproofs.h"

const size_t SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH
    = SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_;

/* this type must be completed before any of the modules/bulletproofs includes */
struct secp256k1_bulletproofs_generators {
    size_t n;
    /* n total generators; set n = 2*k to get G_i and H_i values for i in [1..k] */
    secp256k1_ge* gens;
};

#include "include/secp256k1_bulletproofs.h"
#include "include/secp256k1_generator.h"
#include "modules/bulletproofs/rangeproof_uncompressed_impl.h"
#include "modules/generator/main_impl.h" /* for generator_{load, save} and pedersen_commitment_load */
#include "hash.h"
#include "util.h"

secp256k1_bulletproofs_generators *secp256k1_bulletproofs_generators_create(const secp256k1_context *ctx, size_t n) {
    secp256k1_bulletproofs_generators *ret;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    size_t i;

    VERIFY_CHECK(ctx != NULL);

    ret = (secp256k1_bulletproofs_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (secp256k1_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }
    ret->n = n;

    secp256k1_fe_get_b32(&seed[0], &secp256k1_ge_const_g.x);
    secp256k1_fe_get_b32(&seed[32], &secp256k1_ge_const_g.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, 64);
    for (i = 0; i < n; i++) {
        secp256k1_generator gen;
        unsigned char tmp[32] = { 0 };
        secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, 32);
        CHECK(secp256k1_generator_generate(ctx, &gen, tmp));
        secp256k1_generator_load(&ret->gens[i], &gen);
    }

    return ret;
}

secp256k1_bulletproofs_generators* secp256k1_bulletproofs_generators_parse(const secp256k1_context* ctx, const unsigned char* data, size_t data_len) {
    size_t n = data_len / 33;
    secp256k1_bulletproofs_generators* ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(data != NULL);

    if (data_len % 33 != 0) {
        return NULL;
    }

    ret = (secp256k1_bulletproofs_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->n = n;
    ret->gens = (secp256k1_ge*)checked_malloc(&ctx->error_callback, n * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }

    while (n--) {
        secp256k1_generator gen;
        if (!secp256k1_generator_parse(ctx, &gen, &data[33 * n])) {
            free(ret->gens);
            free(ret);
            return NULL;
        }
        secp256k1_generator_load(&ret->gens[n], &gen);
    }
    return ret;
}

int secp256k1_bulletproofs_generators_serialize(const secp256k1_context* ctx, const secp256k1_bulletproofs_generators* gens, unsigned char* data, size_t *data_len) {
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(data_len != NULL);

    memset(data, 0, *data_len);
    if (*data_len < 33 * gens->n) {
        return 0;
    }
    for (i = 0; i < gens->n; i++) {
        secp256k1_generator gen;
        secp256k1_generator_save(&gen, &gens->gens[i]);
        secp256k1_generator_serialize(ctx, &data[33 * i], &gen);
    }

    *data_len = 33 * gens->n;
    return 1;
}

void secp256k1_bulletproofs_generators_destroy(const secp256k1_context* ctx, secp256k1_bulletproofs_generators *gens) {
    VERIFY_CHECK(ctx != NULL);
    (void) ctx;
    if (gens != NULL) {
        free(gens->gens);
        free(gens);
    }
}

size_t secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(const secp256k1_context* ctx, size_t n_bits) {
    VERIFY_CHECK(ctx != NULL);
    if (n_bits > 64) {
        return 0;
    }
    return SECP256K1_BULLETPROOFS_UNCOMPRESSED_SIZE(n_bits);
}

static int bulletproofs_rangeproof_uncompressed_prove(
    const secp256k1_context* ctx,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_ge *h,
    const secp256k1_ge *g,
    unsigned char* proof,
    size_t* plen,
    const size_t n_bits,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* blind,
    const unsigned char* nonce,
    const unsigned char* enc_data,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    secp256k1_bulletproofs_prover_context prover_ctx;
    secp256k1_ge commitp;
    secp256k1_scalar blinds, enc_datas;
    size_t i;
    int overflow;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(h != NULL);
    ARG_CHECK(g != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(plen != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);

    i = secp256k1_bulletproofs_rangeproof_uncompressed_proof_length(ctx, n_bits);
    if (*plen >= i) {
        *plen = i;
    } else {
        return 0;
    }

    secp256k1_scalar_set_b32(&blinds, blind, &overflow);
    if (overflow) {
        return 0;
    }

    if (enc_data == NULL) {
        secp256k1_scalar_clear(&enc_datas);
    } else {
        secp256k1_scalar_set_b32(&enc_datas, enc_data, &overflow);
        if (overflow) {
            return 0;
        }
    }

    secp256k1_pedersen_commitment_load(&commitp, commit);

    ret = ret && secp256k1_bulletproofs_rangeproof_uncompressed_prove_step0_impl(
        &prover_ctx,
        &proof[0],
        n_bits,
        value,
        min_value,
        &commitp,
	h,
	g,
        gens,
        nonce,
        &enc_datas,
        extra_commit,
        extra_commit_len
    );

    ret = ret && secp256k1_bulletproofs_rangeproof_uncompressed_prove_step1_impl(
        &prover_ctx,
        &proof[65],
        n_bits,
        value,
        min_value,
	h,
	g,
        nonce
    );

    ret = ret && secp256k1_bulletproofs_rangeproof_uncompressed_prove_step2_impl(
        &prover_ctx,
        &proof[130],
        nonce,
        &blinds,
        &enc_datas
    );

    for (i = 0; i < n_bits; i++) {
        ret = ret && secp256k1_bulletproofs_rangeproof_uncompressed_prove_step3_impl(
            &prover_ctx,
            &proof[194 + 64 * i],
            i,
            value,
            min_value,
            nonce
        );
    }

    secp256k1_scalar lr, l, r, t;
    secp256k1_scalar_clear(&lr);
    for (i = 0; i < n_bits; i++) {
	    int overflow;
	    secp256k1_scalar_set_b32(&l, &proof[194 + 64 * i], &overflow);
	    secp256k1_scalar_set_b32(&r, &proof[194 + 64 * i + 32], &overflow);
	    secp256k1_scalar_mul(&t, &l, &r);
	    secp256k1_scalar_add(&lr, &lr, &t);
    }
    print_s(&lr, "Th");

    return ret;
}

static int bulletproofs_rangeproof_uncompressed_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_ge *h,
    const secp256k1_ge *g,
    const unsigned char* proof,
    const size_t plen,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
    unsigned char pk_buf[33];
    const size_t n_bits = (plen - 194) / 64;
    secp256k1_ge commitp;
    secp256k1_ge ap, sp;
    secp256k1_ge t1p, t2p;
    secp256k1_scalar l_dot_r;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(gens != NULL);
    ARG_CHECK(h != NULL);
    ARG_CHECK(g != NULL);
    ARG_CHECK(proof != NULL);
    ARG_CHECK(commit != NULL);
    ARG_CHECK(extra_commit != NULL || extra_commit_len == 0);

    if (n_bits > 64 || plen < 194 || (plen - 194) % 64 != 0) {
        return 0;
    }

    secp256k1_pedersen_commitment_load(&commitp, commit);

    pk_buf[0] = 2 | (proof[0] >> 1);
    memcpy(&pk_buf[1], &proof[1], 32);
    if (!secp256k1_eckey_pubkey_parse(&ap, pk_buf, sizeof(pk_buf))) {
        return 0;
    }
    pk_buf[0] = 2 | (proof[0] & 1);
    memcpy(&pk_buf[1], &proof[33], 32);
    if (!secp256k1_eckey_pubkey_parse(&sp, pk_buf, sizeof(pk_buf))) {
        return 0;
    }

    pk_buf[0] = 2 | (proof[65] >> 1);
    memcpy(&pk_buf[1], &proof[66], 32);
    if (!secp256k1_eckey_pubkey_parse(&t1p, pk_buf, sizeof(pk_buf))) {
        return 0;
    }
    pk_buf[0] = 2 | (proof[65] & 1);
    memcpy(&pk_buf[1], &proof[98], 32);
    if (!secp256k1_eckey_pubkey_parse(&t2p, pk_buf, sizeof(pk_buf))) {
        return 0;
    }

    secp256k1_scalar_clear(&l_dot_r);
    for (i = 0; i < n_bits; i++) {
        int overflow;
        secp256k1_scalar l, r;
        secp256k1_scalar_set_b32(&l, &proof[194 + 64 * i], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_set_b32(&r, &proof[194 + 64 * i + 32], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_mul(&l, &l, &r);
        secp256k1_scalar_add(&l_dot_r, &l_dot_r, &l);
    }

    return secp256k1_bulletproofs_rangeproof_uncompressed_verify_impl(
        ctx,
        scratch,
        proof,
        &l_dot_r,
        n_bits,
        min_value,
        &commitp,
        h,
	g,
        &ap,
        &sp,
        &t1p,
        &t2p,
        gens,
        extra_commit,
        extra_commit_len
    );
}

int secp256k1_bulletproofs_rangeproof_uncompressed_prove(
    const secp256k1_context* ctx,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_generator* asset_gen,
    unsigned char* proof,
    size_t* plen,
    const size_t n_bits,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* blind,
    const unsigned char* nonce,
    const unsigned char* enc_data,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
	secp256k1_ge asset_genp;

	secp256k1_generator_load(&asset_genp, asset_gen);
	return bulletproofs_rangeproof_uncompressed_prove(ctx, gens, &secp256k1_ge_const_g /* h */, &asset_genp /* g */, proof, plen, n_bits, value, min_value, commit, blind, nonce, enc_data, extra_commit, extra_commit_len);
}

int secp256k1_bulletproofs_rangeproof_uncompressed_elgamal_prove(
    const secp256k1_context* ctx,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_generator* genh,
    unsigned char* proof,
    size_t* plen,
    const size_t n_bits,
    const uint64_t value,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* blind,
    const unsigned char* nonce,
    const unsigned char* enc_data,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
	secp256k1_ge h;

	secp256k1_generator_load(&h, genh);
	return bulletproofs_rangeproof_uncompressed_prove(ctx, gens, &h, &secp256k1_ge_const_g /* g */, proof, plen, n_bits, value, min_value, commit, blind, nonce, enc_data, extra_commit, extra_commit_len);
}

int secp256k1_bulletproofs_rangeproof_uncompressed_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_generator* asset_gen,
    const unsigned char* proof,
    const size_t plen,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
	secp256k1_ge asset_genp;

	secp256k1_generator_load(&asset_genp, asset_gen);
	return bulletproofs_rangeproof_uncompressed_verify(ctx, scratch, gens, &secp256k1_ge_const_g /* h */, &asset_genp /* g */, proof, plen, min_value, commit, extra_commit, extra_commit_len);
}

int secp256k1_bulletproofs_rangeproof_uncompressed_elgamal_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_bulletproofs_generators* gens,
    const secp256k1_generator* genh,
    const unsigned char* proof,
    const size_t plen,
    const uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const unsigned char* extra_commit,
    size_t extra_commit_len
) {
	secp256k1_ge h;

	secp256k1_generator_load(&h, genh);
	return bulletproofs_rangeproof_uncompressed_verify(ctx, scratch, gens, &h, &secp256k1_ge_const_g /* g */, proof, plen, min_value, commit, extra_commit, extra_commit_len);
}

#endif
