/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_MAIN_
#define _SECP256K1_MODULE_MUSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_musig.h"
#include "hash.h"

int secp256k1_musig_partial_signature_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_musig_partial_signature* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out32, sig->data, 32);
    return 1;
}

int secp256k1_musig_partial_signature_parse(const secp256k1_context* ctx, secp256k1_musig_partial_signature* sig, const unsigned char *in32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in32 != NULL);
    memcpy(sig->data, in32, 32);
    return 1;
}

static void secp256k1_musig_coefficient(secp256k1_scalar *r, const unsigned char *ell, size_t idx) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, ell, 32);
    while (idx > 0) {
        unsigned char c = idx;
        secp256k1_sha256_write(&sha, &c, 1);
        idx /= 0x100;
    }
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(r, buf, NULL);
}

static int secp256k1_musig_compute_ell(const secp256k1_context *ctx, unsigned char *ell, const secp256k1_pubkey *pk, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t serlen = sizeof(ser);
        if (!secp256k1_ec_pubkey_serialize(ctx, ser, &serlen, &pk[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        secp256k1_sha256_write(&sha, ser, serlen);
    }
    secp256k1_sha256_finalize(&sha, ell);
    return 1;
}

int secp256k1_musig_session_initialize(const secp256k1_context* ctx, secp256k1_musig_session *session, unsigned char *nonce_commitment, const unsigned char *session_id, const unsigned char *msg32, const secp256k1_pubkey *combined_pk, const unsigned char *pk_hash, size_t my_index, const unsigned char *sec_key) {
    unsigned char combined_ser[33];
    size_t combined_ser_size = sizeof(combined_ser);
    int overflow;
    secp256k1_scalar x;
    secp256k1_scalar y;
    secp256k1_sha256 sha;
    secp256k1_gej rj;
    secp256k1_ge rp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(session != NULL);
    ARG_CHECK(nonce_commitment != NULL);
    ARG_CHECK(session_id != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pk_hash != NULL);
    ARG_CHECK(sec_key != NULL);

    memcpy(session->msg32, msg32, 32);
    memcpy(&session->combined_pk, combined_pk, sizeof(*combined_pk));
    memcpy(session->pk_hash, pk_hash, 32);
    session->nonce_is_set = 0;
    session->has_secret_data = 1;

    /* Compute secret key */
    secp256k1_scalar_set_b32(&x, sec_key, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_musig_coefficient(&y, pk_hash, my_index);
    secp256k1_scalar_mul(&x, &x, &y);
    secp256k1_scalar_get_b32(session->sec_key, &x);

    /* Compute secret nonce */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, sec_key, 32);
    secp256k1_sha256_write(&sha, session_id, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_ec_pubkey_serialize(ctx, combined_ser, &combined_ser_size, combined_pk, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, combined_ser, combined_ser_size);
    secp256k1_sha256_finalize(&sha, session->sec_nonce);
    secp256k1_scalar_set_b32(&x, session->sec_nonce, &overflow);
    if (overflow) {
        return 0;
    }

    /* Compute public nonce and commitment */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &x);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&session->pub_nonce, &rp);

    if (nonce_commitment != NULL) {
        unsigned char commit[33];
        size_t commit_size = sizeof(commit);
        secp256k1_sha256_initialize(&sha);
        secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, &session->pub_nonce, SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, commit, commit_size);
        secp256k1_sha256_finalize(&sha, nonce_commitment);
    }

    return 1;
}

int secp256k1_musig_session_initialize_public(const secp256k1_context* ctx, secp256k1_musig_session *session, const unsigned char *msg32, const secp256k1_pubkey *combined_pk, const unsigned char *pk_hash) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pk_hash != NULL);
    (void) ctx;

    memcpy(session->msg32, msg32, 32);
    memcpy(&session->combined_pk, combined_pk, sizeof(*combined_pk));
    memcpy(session->pk_hash, pk_hash, 32);
    session->nonce_is_set = 0;
    session->has_secret_data = 0;

    return 1;
}

int secp256k1_musig_session_public_nonce(const secp256k1_context* ctx, secp256k1_pubkey *nonce, const secp256k1_musig_session *session, const secp256k1_musig_signer_data *signer, size_t n) {
    static const unsigned char zero32[32] = {0};
    size_t i;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signer != NULL);

    /* Check that we have all commitments */
    for (i = 0; i < n; i++) {
        if (memcmp(signer[i].nonce_commitment, zero32, sizeof(zero32)) == 0) {
            return 0;
        }
    }
    if (session->has_secret_data) {
        memcpy(nonce, &session->pub_nonce, sizeof(*nonce));
        return 1;
    } else {
        return 0;
    }
}

int secp256k1_musig_session_combine_nonces(const secp256k1_context* ctx, secp256k1_musig_session *session, const secp256k1_musig_signer_data *signer, size_t n) {
    secp256k1_gej combined_noncej;
    secp256k1_ge combined_noncep;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signer != NULL);
    ARG_CHECK(n > 0);

    secp256k1_gej_set_infinity(&combined_noncej);
    for (i = 0; i < n; i++) {
        secp256k1_ge noncep;
        if (!signer[i].present) {
            return 0;
        }
        secp256k1_pubkey_load(ctx, &noncep, &signer[i].nonce);
        secp256k1_gej_add_ge_var(&combined_noncej, &combined_noncej, &noncep, NULL);
    }
    secp256k1_ge_set_gej(&combined_noncep, &combined_noncej);
    if (secp256k1_fe_is_quad_var(&combined_noncep.y)) {
        session->nonce_is_negated = 0;
    } else {
        session->nonce_is_negated = 1;
        secp256k1_ge_neg(&combined_noncep, &combined_noncep);
    }
    secp256k1_pubkey_save(&session->combined_nonce, &combined_noncep);
    session->nonce_is_set = 1;
    return 1;
}

int secp256k1_musig_set_nonce_commitments(const secp256k1_context* ctx, secp256k1_musig_signer_data *signer, const unsigned char *const *commitments, size_t n) {
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(signer != NULL);
    ARG_CHECK(commitments != NULL);
    for (i = 0; i < n; i++) {
        ARG_CHECK(commitments[i] != NULL);
    }

    for (i = 0; i < n; i++) {
        memcpy(signer[i].nonce_commitment, commitments[i], 32);
    }
    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    unsigned char ell[32];
    const secp256k1_pubkey *pks;
} secp256k1_musig_pubkey_combine_ecmult_data;

static int secp256k1_musig_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_pubkey_combine_ecmult_data *ctx = (secp256k1_musig_pubkey_combine_ecmult_data *) data;
    secp256k1_musig_coefficient(sc, ctx->ell, idx);
    return secp256k1_pubkey_load(ctx->ctx, pt, &ctx->pks[idx]);
}

int secp256k1_musig_pubkey_combine(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, secp256k1_pubkey *combined_pk, unsigned char *pk_hash, secp256k1_musig_signer_data *signer_data, const secp256k1_pubkey *pks, size_t n) {
    secp256k1_musig_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pks != NULL);
    ARG_CHECK(n > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pks;
    if (!secp256k1_musig_compute_ell(ctx, ecmult_data.ell, pks, n)) {
        return 0;
    }
    if (!secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_musig_pubkey_combine_callback, (void *) &ecmult_data, n)) {
        return 0;
    }
    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_pubkey_save(combined_pk, &pkp);

    if (pk_hash != NULL) {
        memcpy(pk_hash, ecmult_data.ell, 32);
    }

    if (signer_data != NULL) {
        size_t i;
        for (i = 0; i < n; i++) {
            memset(&signer_data[i], 0, sizeof(signer_data[i]));
            memcpy(&signer_data[i].pubkey, &pks[i], sizeof(pks[i]));
            signer_data[i].index = i;
        }
    }

    return 1;
}

int secp256k1_musig_set_nonce(const secp256k1_context* ctx, secp256k1_musig_signer_data *data, const secp256k1_pubkey *pubnon) {
    unsigned char commit[33];
    size_t commit_size = sizeof(commit);
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(pubnon != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, pubnon, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, commit, commit_size);
    secp256k1_sha256_finalize(&sha, commit);

    if (memcmp(commit, data->nonce_commitment, 32) != 0) {
        return 0;
    }
    memcpy(&data->nonce, pubnon, sizeof(*pubnon));
    data->present = 1;
    return 1;
}

static void secp256k1_musig_compute_messagehash(const secp256k1_context *ctx, unsigned char *out32, const secp256k1_musig_session *session) {
    unsigned char buf[33];
    size_t bufsize = 33;
    secp256k1_ge rp;
    secp256k1_sha256 sha;

    secp256k1_sha256_initialize(&sha);
    secp256k1_pubkey_load(ctx, &rp, &session->combined_nonce);
    secp256k1_fe_get_b32(buf, &rp.x);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_ec_pubkey_serialize(ctx, buf, &bufsize, &session->combined_pk, SECP256K1_EC_COMPRESSED);
    VERIFY_CHECK(bufsize == 33);
    secp256k1_sha256_write(&sha, buf, bufsize);
    secp256k1_sha256_write(&sha, session->msg32, 32);
    secp256k1_sha256_finalize(&sha, out32);
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_session *session) {
    unsigned char msghash[32];
    int overflow;
    secp256k1_scalar sk;
    secp256k1_scalar e, k;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(session != NULL);

    if (!session->nonce_is_set || !session->has_secret_data) {
        return 0;
    }

    secp256k1_scalar_set_b32(&sk, session->sec_key, &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_scalar_set_b32(&k, session->sec_nonce, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k)) {
        return 0;
    }
    if (session->nonce_is_negated) {
        secp256k1_scalar_negate(&k, &k);
    }

    /* build message hash */
    secp256k1_musig_compute_messagehash(ctx, msghash, session);
    secp256k1_scalar_set_b32(&e, msghash, NULL);

    /* Sign */
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&partial_sig->data[0], &e);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&k);

    return 1;
}

int secp256k1_musig_partial_sig_combine(const secp256k1_context* ctx, secp256k1_schnorrsig *sig, const secp256k1_musig_partial_signature *partial_sig, size_t n_sigs, const secp256k1_musig_session *session) {
    size_t i;
    secp256k1_scalar s;
    secp256k1_ge noncep;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(session != NULL);

    if (!session->nonce_is_set) {
        return 0;
    }

    secp256k1_scalar_clear(&s);
    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;

        secp256k1_scalar_set_b32(&term, partial_sig[i].data, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_add(&s, &s, &term);
    }

    secp256k1_pubkey_load(ctx, &noncep, &session->combined_nonce);
    VERIFY_CHECK(secp256k1_fe_is_quad_var(&noncep.y));
    secp256k1_fe_normalize(&noncep.x);
    secp256k1_fe_get_b32(&sig->data[0], &noncep.x);
    secp256k1_scalar_get_b32(&sig->data[32], &s);

    return 1;
}

int secp256k1_musig_adaptor_extract(const secp256k1_context* ctx, secp256k1_pubkey *pub_adaptor, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_session *session, const secp256k1_musig_signer_data *signer) {
    unsigned char msghash[32];
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_scalar mu;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pub_adaptor != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signer != NULL);

    if (!signer->present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_musig_compute_messagehash(ctx, msghash, session);
    secp256k1_scalar_set_b32(&e, msghash, NULL);

    /* Multiplying the messagehash by the musig coefficient is equivalent
     * to multiplying the signer's public key by the coefficient, except
     * much easier to do. */
    secp256k1_musig_coefficient(&mu, session->pk_hash, signer->index);
    secp256k1_scalar_mul(&e, &e, &mu);

    if (!secp256k1_pubkey_load(ctx, &rp, &signer->nonce)) {
        return 0;
    }
    secp256k1_gej_set_ge(&rj, &rp);

    if (!secp256k1_schnorrsig_real_verify(ctx, &rj, &s, &e, &signer->pubkey)) {
        return 0;
    }
    if (!session->nonce_is_negated) {
        secp256k1_ge_neg(&rp, &rp);
    }

    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);
    if (secp256k1_gej_is_infinity(&rj)) {
        return 0;
    }

    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(pub_adaptor, &rp);
    return 1;
}

int secp256k1_musig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_session *session, const secp256k1_musig_signer_data *signer) {
    unsigned char msghash[32];
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_scalar mu;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(signer != NULL);

    if (!session->nonce_is_set || !signer->present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_musig_compute_messagehash(ctx, msghash, session);
    secp256k1_scalar_set_b32(&e, msghash, NULL);

    /* Multiplying the messagehash by the musig coefficient is equivalent
     * to multiplying the signer's public key by the coefficient, except
     * much easier to do. */
    secp256k1_musig_coefficient(&mu, session->pk_hash, signer->index);
    secp256k1_scalar_mul(&e, &e, &mu);

    if (!secp256k1_pubkey_load(ctx, &rp, &signer->nonce)) {
        return 0;
    }

    if (!secp256k1_schnorrsig_real_verify(ctx, &rj, &s, &e, &signer->pubkey)) {
        return 0;
    }
    if (!session->nonce_is_negated) {
        secp256k1_ge_neg(&rp, &rp);
    }
    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);

    return secp256k1_gej_is_infinity(&rj);
}

int secp256k1_musig_partial_to_adaptor_sig(const secp256k1_context* ctx, secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_partial_signature *adaptor_sig, const unsigned char *sec_adaptor) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(sec_adaptor != NULL);

    secp256k1_scalar_set_b32(&s, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor, &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(partial_sig->data, &s);
    return 1;
}

int secp256k1_musig_adaptor_to_partial_sig(const secp256k1_context* ctx, secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_partial_signature *adaptor_sig, const unsigned char *sec_adaptor) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(sec_adaptor != NULL);

    secp256k1_scalar_set_b32(&s, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&t, &t);

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(partial_sig->data, &s);
    return 1;
}

int secp256k1_musig_extract_secret_adaptor(const secp256k1_context* ctx, unsigned char *sec_adaptor, const secp256k1_schnorrsig *sig, const secp256k1_musig_partial_signature *adaptor_sig, const secp256k1_musig_partial_signature *partial_sig) {
    secp256k1_scalar t;
    secp256k1_scalar s;
    int overflow;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    
    secp256k1_scalar_set_b32(&t, &sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&t, &t);

    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_add(&t, &t, &s);

    secp256k1_scalar_set_b32(&s, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_add(&t, &t, &s);

    secp256k1_scalar_get_b32(sec_adaptor, &t);
    return 1;
}

#endif
