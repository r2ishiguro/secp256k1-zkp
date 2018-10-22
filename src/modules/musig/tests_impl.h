/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

void musig_api_tests(secp256k1_scratch_space *scratch) {
    secp256k1_musig_session session[3];
    secp256k1_musig_signer_data signer0[2];
    secp256k1_musig_signer_data signer1[2];
    secp256k1_musig_signer_data signer2[2];
    secp256k1_musig_partial_signature partial_sig[2];
    secp256k1_schnorrsig final_sig;
    secp256k1_schnorrsig final_sig_cmp;

    unsigned char buf[32];
    unsigned char sk[2][32];
    unsigned char session_id[2][32];
    unsigned char nonce_commitment[2][32];
    unsigned char msg[32];
    secp256k1_pubkey combined_pk;
    unsigned char pk_hash[32];
    secp256k1_pubkey pk[2];

    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    secp256k1_pubkey adaptor1;
    secp256k1_musig_partial_signature adaptor_sig;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);

    secp256k1_rand256(session_id[0]);
    secp256k1_rand256(session_id[1]);
    secp256k1_rand256(sk[0]);
    secp256k1_rand256(sk[1]);
    secp256k1_rand256(msg);
    secp256k1_rand256(sec_adaptor);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[0], sk[0]) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[1], sk[1]) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);

    /** main test body **/

    /* Key combination */
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_combine(none, scratch, &combined_pk, pk_hash, signer0, pk, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey_combine(sign, scratch, &combined_pk, pk_hash, signer0, pk, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer0, pk, 2) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, NULL, &combined_pk, pk_hash, signer0, pk, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, NULL, pk_hash, signer0, pk, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, NULL, signer0, pk, 2) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, NULL, pk, 2) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer0, NULL, 2) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer0, pk, 0) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer0, NULL, 0) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer0, pk, 2) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer1, pk, 2) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, signer2, pk, 2) == 1);

    /** Session creation **/
    ecount = 0;
    CHECK(secp256k1_musig_session_initialize(none, &session[0], nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_session_initialize(vrfy, &session[0], nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, 0, sk[0]) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_initialize(sign, NULL, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], NULL, session_id[0], msg, &combined_pk, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], NULL, msg, &combined_pk, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], session_id[0], NULL, &combined_pk, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], session_id[0], msg, NULL, pk_hash, 0, sk[0]) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], session_id[0], msg, &combined_pk, NULL, 0, sk[0]) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, 0, NULL) == 0);
    CHECK(ecount == 9);

    CHECK(secp256k1_musig_session_initialize_public(none, &session[2], msg, &combined_pk, pk_hash) == 1);
    CHECK(ecount == 9);
    CHECK(secp256k1_musig_session_initialize_public(none, NULL, msg, &combined_pk, pk_hash) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_musig_session_initialize_public(none, &session[2], NULL, &combined_pk, pk_hash) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_musig_session_initialize_public(none, &session[2], msg, NULL, pk_hash) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_musig_session_initialize_public(none, &session[2], msg, &combined_pk, NULL) == 0);
    CHECK(ecount == 13);

    CHECK(secp256k1_musig_session_initialize(sign, &session[0], nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, 0, sk[0]) == 1);
    CHECK(secp256k1_musig_session_initialize(sign, &session[1], nonce_commitment[1], session_id[1], msg, &combined_pk, pk_hash, 1, sk[1]) == 1);

    /** Signing step 0 -- exchange nonce commitments */
    ecount = 0;
    {
        secp256k1_pubkey nonce;
        const unsigned char *ncs[2];
        ncs[0] = nonce_commitment[0];
        ncs[1] = nonce_commitment[1];

        /* Can't obtain public nonce or sign until commitments have been exchanged */
        CHECK(secp256k1_musig_session_public_nonce(none, &nonce, &session[0], signer0, 2) == 0);
        CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &session[0]) == 0);
        CHECK(ecount == 0);

        CHECK(secp256k1_musig_set_nonce_commitments(none, signer0, ncs, 2) == 1);
        CHECK(ecount == 0);
        CHECK(secp256k1_musig_set_nonce_commitments(none, NULL, ncs, 2) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_set_nonce_commitments(none, signer0, NULL, 2) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_musig_set_nonce_commitments(none, signer0, ncs, 0) == 1);
        CHECK(ecount == 2);

        ncs[0] = NULL;
        CHECK(secp256k1_musig_set_nonce_commitments(none, signer0, ncs, 2) == 0);
        CHECK(ecount == 3);
        ncs[0] = nonce_commitment[0];
        ncs[1] = NULL;
        CHECK(secp256k1_musig_set_nonce_commitments(none, signer0, ncs, 2) == 0);
        CHECK(ecount == 4);
        ncs[1] = nonce_commitment[1];

        CHECK(secp256k1_musig_set_nonce_commitments(none, signer0, ncs, 2) == 1);
        CHECK(secp256k1_musig_set_nonce_commitments(none, signer1, ncs, 2) == 1);
        CHECK(secp256k1_musig_set_nonce_commitments(none, signer2, ncs, 2) == 1);

        /* Can obtain public nonce after commitments have been exchanged; still can't sign */
        CHECK(secp256k1_musig_session_public_nonce(none, &nonce, &session[0], signer0, 2) == 1);
        CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &session[0]) == 0);
        CHECK(ecount == 4);
    }

    /** Signing step 1 -- exchange nonces */
    ecount = 0;
    {
        secp256k1_pubkey public_nonce[2];

        CHECK(secp256k1_musig_session_public_nonce(none, &public_nonce[0], &session[0], signer0, 2) == 1);
        CHECK(ecount == 0);
        CHECK(secp256k1_musig_session_public_nonce(none, NULL, &session[0], signer0, 2) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_session_public_nonce(none, &public_nonce[0], NULL, signer0, 2) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_musig_session_public_nonce(none, &public_nonce[0], &session[0], NULL, 2) == 0);
        CHECK(ecount == 3);

        CHECK(secp256k1_musig_session_public_nonce(none, &public_nonce[0], &session[0], signer0, 2) == 1);
        CHECK(secp256k1_musig_session_public_nonce(none, &public_nonce[1], &session[1], signer1, 2) == 1);

        CHECK(secp256k1_musig_set_nonce(none, &signer0[0], &public_nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer0[1], &public_nonce[0]) == 0);
        CHECK(secp256k1_musig_set_nonce(none, &signer0[1], &public_nonce[1]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer0[1], &public_nonce[1]) == 1);
        CHECK(ecount == 3);

        CHECK(secp256k1_musig_set_nonce(none, NULL, &public_nonce[0]) == 0);
        CHECK(ecount == 4);
        CHECK(secp256k1_musig_set_nonce(none, &signer1[0], NULL) == 0);
        CHECK(ecount == 5);

        CHECK(secp256k1_musig_set_nonce(none, &signer1[0], &public_nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer1[1], &public_nonce[1]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer2[0], &public_nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer2[1], &public_nonce[1]) == 1);

        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], signer0, 2) == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, NULL, signer0, 2) == 0);
        CHECK(ecount == 6);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], NULL, 2) == 0);
        CHECK(ecount == 7);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], signer0, 0) == 0);
        CHECK(ecount == 8);

        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], signer0, 2) == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[1], signer0, 2) == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[2], signer0, 2) == 1);
    }

    /** Signing step 2 -- partial signatures */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &session[0]) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_partial_sign(none, NULL, &session[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &session[0]) == 1);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[1], &session[1]) == 1);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[2], &session[2]) == 0);  /* observer can't sign */
    CHECK(ecount == 2);

    ecount = 0;
    CHECK(secp256k1_musig_partial_signature_serialize(none, buf, &partial_sig[0]) == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, buf, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], buf) == 1);
    CHECK(secp256k1_musig_partial_signature_parse(none, NULL, buf) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 4);

    /** Partial signature verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_verify(none, &partial_sig[0], &session[0], &signer0[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_verify(sign, &partial_sig[0], &session[0], &signer0[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &session[0], &signer0[0]) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &session[0], &signer0[0]) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_partial_sig_verify(vrfy, NULL, &session[0], &signer0[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], NULL, &signer0[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &session[0], NULL) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &session[0], &signer0[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &session[1], &signer1[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &session[2], &signer2[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &session[0], &signer0[1]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &session[1], &signer1[1]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &session[2], &signer2[1]) == 1);
    CHECK(ecount == 5);

    /* attempting `adaptor_extract` on an ordinary signature should fail gracefully */
    CHECK(secp256k1_musig_adaptor_extract(vrfy, &adaptor1, &partial_sig[0], &session[0], &signer0[0]) == 0);
    CHECK(ecount == 5);

    /** Adaptor signature verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_to_adaptor_sig(none, &adaptor_sig, &partial_sig[0], sec_adaptor) == 1);
    CHECK(secp256k1_musig_partial_to_adaptor_sig(none, NULL, &partial_sig[0], sec_adaptor) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_to_adaptor_sig(none, &adaptor_sig, NULL, sec_adaptor) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_to_adaptor_sig(none, &adaptor_sig, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_musig_adaptor_extract(none, &adaptor1, &adaptor_sig, &session[0], &signer0[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_adaptor_extract(sign, &adaptor1, &adaptor_sig, &session[0], &signer0[0]) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_adaptor_extract(vrfy, &adaptor1, &adaptor_sig, &session[0], &signer0[0]) == 1);
    CHECK(secp256k1_musig_adaptor_extract(vrfy, &adaptor1, &adaptor_sig, &session[2], &signer0[0]) == 1); /* works w public session */
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_adaptor_extract(vrfy, NULL, &adaptor_sig, &session[0], &signer0[0]) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_adaptor_extract(vrfy, &adaptor1, NULL, &session[0], &signer0[0]) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_adaptor_extract(vrfy, &adaptor1, &adaptor_sig, NULL, &signer0[0]) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_adaptor_extract(vrfy, &adaptor1, &adaptor_sig, &session[0], NULL) == 0);
    CHECK(ecount == 9);

    /* Correct adaptor was extracted */
    CHECK(memcmp(&adaptor, &adaptor1, sizeof(adaptor)) == 0);

    /* Signature comes out unscathed */
    CHECK(secp256k1_musig_adaptor_to_partial_sig(none, &partial_sig[0], &adaptor_sig, sec_adaptor) == 1);
    CHECK(secp256k1_musig_adaptor_to_partial_sig(none, NULL, &adaptor_sig, sec_adaptor) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_musig_adaptor_to_partial_sig(none, &partial_sig[0], NULL, sec_adaptor) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_musig_adaptor_to_partial_sig(none, &partial_sig[0], &adaptor_sig, NULL) == 0);
    CHECK(ecount == 12);

    /** Signing combining and verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_combine(none, &final_sig, partial_sig, 2, &session[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, &final_sig_cmp, partial_sig, 2, &session[0]) == 1);
    CHECK(memcmp(&final_sig, &final_sig_cmp, sizeof(final_sig)) == 0);
    CHECK(secp256k1_musig_partial_sig_combine(none, &final_sig_cmp, partial_sig, 2, &session[0]) == 1);
    CHECK(memcmp(&final_sig, &final_sig_cmp, sizeof(final_sig)) == 0);

    CHECK(secp256k1_musig_partial_sig_combine(none, NULL, partial_sig, 2, &session[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, &final_sig, NULL, 2, &session[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_combine(none, &final_sig, partial_sig, 2, NULL) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_schnorrsig_verify(vrfy, &final_sig, msg, &combined_pk) == 1);

    /** Secret adaptor can be extracted from signature */
    ecount = 0;
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, &adaptor_sig, &partial_sig[1]) == 1);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, NULL, &final_sig, &adaptor_sig, &partial_sig[1]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, NULL, &adaptor_sig, &partial_sig[1]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, NULL, &partial_sig[1]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, &adaptor_sig, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(memcmp(sec_adaptor, sec_adaptor1, 32) == 0);

    /** cleanup **/
    memset(&session, 0, sizeof(session));
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
}

#if 0
void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    /* Thoughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    secp256k1_schnorrsig final_sig_a;
    secp256k1_schnorrsig final_sig_b;
    secp256k1_musig_partial_signature partial_sig_a[2];
    secp256k1_musig_partial_signature partial_sig_b[2];
    secp256k1_musig_partial_signature adaptor_sig_a;
    secp256k1_musig_partial_signature adaptor_sig_b;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor_a;
    secp256k1_pubkey pub_adaptor_b;
    secp256k1_musig_validation_aux aux_a;
    secp256k1_musig_validation_aux aux_b;

    unsigned char seckey_a[2][32];
    unsigned char seckey_b[2][32];
    secp256k1_musig_secret_key tweak_seckey_a[2];
    secp256k1_musig_secret_key tweak_seckey_b[2];
    secp256k1_pubkey pk_a[2];
    secp256k1_pubkey pk_b[2];
    secp256k1_pubkey combine_pk_a;
    secp256k1_pubkey combine_pk_b;
    secp256k1_musig_config musig_config_a;
    secp256k1_musig_config musig_config_b;
    unsigned char secnon_a[2][32];
    unsigned char secnon_b[2][32];
    unsigned char noncommit_a[2][32];
    unsigned char noncommit_b[2][32];
    secp256k1_pubkey pubnon_a[2];
    secp256k1_pubkey pubnon_b[2];
    secp256k1_musig_signer_data data_a[2];
    secp256k1_musig_signer_data data_b[2];

    const unsigned char seed[32] = "still tired of choosing seeds...";
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";

    /* Step 1: key setup */
    secp256k1_rand256(seckey_a[0]);
    secp256k1_rand256(seckey_a[1]);
    secp256k1_rand256(seckey_b[0]);
    secp256k1_rand256(seckey_b[1]);
    secp256k1_rand256(sec_adaptor);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_a[0], seckey_a[0]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_a[1], seckey_a[1]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_b[0], seckey_b[0]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_b[1], seckey_b[1]));

    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_a[0], seckey_a[0], pk_a, 2, 0) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_a[1], seckey_a[1], pk_a, 2, 1) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_b[0], seckey_b[0], pk_b, 2, 0) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_b[1], seckey_b[1], pk_b, 2, 1) == 1);

    CHECK(secp256k1_musig_init(ctx, scratch, &musig_config_a, pk_a, 2));
    CHECK(secp256k1_musig_init(ctx, scratch, &musig_config_b, pk_b, 2));

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_a[0], &pubnon_a[0], noncommit_a[0], &tweak_seckey_a[0], msg32_a, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_a[1], &pubnon_a[1], noncommit_a[1], &tweak_seckey_a[1], msg32_a, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_b[0], &pubnon_b[0], noncommit_b[0], &tweak_seckey_b[0], msg32_b, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_b[1], &pubnon_b[1], noncommit_b[1], &tweak_seckey_b[1], msg32_b, seed));

    secp256k1_musig_signer_data_initialize(ctx, &data_a[0], &musig_config_a, 0, noncommit_a[0]);
    secp256k1_musig_signer_data_initialize(ctx, &data_a[1], &musig_config_a, 1, noncommit_a[1]);
    secp256k1_musig_signer_data_initialize(ctx, &data_b[0], &musig_config_b, 0, noncommit_b[0]);
    secp256k1_musig_signer_data_initialize(ctx, &data_b[1], &musig_config_b, 1, noncommit_b[1]);
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[0], &pubnon_a[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[1], &pubnon_a[1]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[0], &pubnon_b[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[1], &pubnon_b[1]));

    /* Step 2: Signer 0 produces adaptor signatures */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &adaptor_sig_a, &aux_a, secnon_a[0], &musig_config_a, &tweak_seckey_a[0], msg32_a, data_a, 0, sec_adaptor));
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &adaptor_sig_b, &aux_b, secnon_b[0], &musig_config_b, &tweak_seckey_b[0], msg32_b, data_b, 0, sec_adaptor));

    /* Step 3: Signer 1 receives adaptor signatures, checks that they used the same public adaptor, and signs to send B-coins */
    CHECK(secp256k1_musig_adaptor_signature_extract(ctx, &pub_adaptor_a, &adaptor_sig_a, &data_a[0], &aux_a));
    CHECK(secp256k1_musig_adaptor_signature_extract(ctx, &pub_adaptor_b, &adaptor_sig_b, &data_b[0], &aux_b));
    CHECK(memcmp(&pub_adaptor_a, &pub_adaptor_b, sizeof(pub_adaptor_a)) == 0); /* TODO the API says we're not allowed to compare pubkeys like this, but c'mon */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_b[1], &aux_b, secnon_b[1], &musig_config_b, &tweak_seckey_b[1], msg32_b, data_b, 1, NULL));

    /* Step 4: Signer 0 signs to take B-coins, combines signatures and publishes */
    CHECK(secp256k1_musig_adaptor_signature_adapt(ctx, &partial_sig_b[0], &adaptor_sig_b, sec_adaptor));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &final_sig_b, &musig_config_b, partial_sig_b, &aux_b) == 1);
    CHECK(secp256k1_musig_pubkey(ctx, &combine_pk_b, &musig_config_b));
    CHECK(secp256k1_schnorrsig_verify(ctx, &final_sig_b, msg32_b, &combine_pk_b) == 1);

    /* Step 5: Signer 1 extracts secret from published signature, applies it to other adaptor signature, and takes A-coins */
    CHECK(secp256k1_musig_adaptor_signature_extract_secret(ctx, sec_adaptor_extracted, &musig_config_b, &final_sig_b, &adaptor_sig_b, &partial_sig_b[1]) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_adaptor_signature_adapt(ctx, &partial_sig_a[0], &adaptor_sig_a, sec_adaptor_extracted));
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_a[1], &aux_a, secnon_a[1], &musig_config_a, &tweak_seckey_a[1], msg32_a, data_a, 1, NULL));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &final_sig_a, &musig_config_a, partial_sig_a, &aux_a) == 1);
    CHECK(secp256k1_musig_pubkey(ctx, &combine_pk_a, &musig_config_a));
    CHECK(secp256k1_schnorrsig_verify(ctx, &final_sig_a, msg32_a, &combine_pk_a) == 1);

    CHECK(secp256k1_musig_config_destroy(ctx, &musig_config_a));
    CHECK(secp256k1_musig_config_destroy(ctx, &musig_config_b));
}
#endif

void run_musig_tests(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    musig_api_tests(scratch);
/*
    scriptless_atomic_swap(scratch);
*/

    secp256k1_scratch_space_destroy(scratch);
}

#endif
