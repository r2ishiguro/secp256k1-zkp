#ifndef SECP256K1_MUSIG_H
#define SECP256K1_MUSIG_H

/** Data structure containing data related to a single signing session.
 *
 * This structure is not opaque, but it is strongly discouraged to read or write
 * to it directly. A signer who is online throughout the whole process and can
 * keep this structure in memory can use the provided API functions for a
 * safe standard workflow.
 *
 * A signer who goes offline and needs to import/export or save/load this
 * structure **must** take measures prevent replay attacks wherein an old
 * state is loaded and the signing protocol forked from that point. One
 * straightforward way to accomplish this is to attach the output of a
 * monotonic non-resettable counter (hardware support is needed for this).
 * Increment the counter before each output and encrypt+sign the entire
 * package. If a package is deserialized with an old counter state or bad
 * signature it should be rejected.
 *
 * Observe that an independent counter is needed for each concurrent signing
 * session such a device is involved in. To avoid fragility, it is therefore
 * recommended that any offline signer be usable for only a single session
 * at once.
 *
 * Given access to such a counter, its output should be used as (or mixed
 * into) the session ID to ensure uniqueness.
 */
typedef struct {
    /** MuSig-computed combined public key */
    secp256k1_pubkey combined_pk;
    /** TODO should we store the number of signers to verify against in the functions that take signer counts (e.g. secp256k1_musig_session_public_nonce) */
    /** The 32-byte hash of the original public keys */
    unsigned char pk_hash[32];
    /** Summed combined public nonce (undefined if `nonce_is_set` is false) */
    secp256k1_pubkey combined_nonce;
    /** Whether the above nonce has been set */
    int nonce_is_set;
    /** If `nonce_is_set`, whether the above nonce was negated after summing
     *  the particpants' nonces. (Needed to ensure the nonce's y coordinate
     *  has a quadratic-residue y coordinate.) */
    int nonce_is_negated;
    /** The 32-byte message (hash) to be signed */
    unsigned char msg32[32];

    /** Whether this session object has a signers' secret data; if this is `false`,
     *  it may still be used for verification purposes. */
    int has_secret_data;
    /** If `has_secret_data`, the signer's secret key */
    unsigned char sec_key[32];
    /** If `has_secret_data`, the signer's secret nonce */
    unsigned char sec_nonce[32];
    /** If `has_secret_data`, the signer's public nonce */
    secp256k1_pubkey pub_nonce;
} secp256k1_musig_session;

/** Data structure containing data on other signers to be used during signing
 *
 * The workflow for this structure is as follows:
 *
 * 1. This structure is initialized with `secp256k1_musig_pubkey_combine`, which
 *    sets the `pubkey` and `index` fields, and zeros out all other fields.
 *
 * 2. It should be updated with `secp256k1_musig_set_nonce_commitments` which
 *    takes an array of signer data structs and an array of commitments, and
 *    sets each signer data struct's `nonce_commitment` field to the corresponding
 *    commitment. This function cannot fail provided the function contract (no NULL
 *    arguments) is upheld.
 *
 * 3. Each individual data struct should be updated with `secp256k1_musig_set_nonce`
 *    once a nonce is available. This function takes a single signer data struct
 *    rather than an array because it may fail in the case that the provided nonce
 *    does not match the commitment. In this case, it is desireable to identify
 *    the exact party whose nonce was inconsistent.
 *
 *    If this function succeeds, it sets `present` to 1.
 * 
 * The structure is must only be used in a SINGLE signing attempt.
 *
 * Fields:
 *   present: flag indicating whether the signer provided its nonce
 *     index: index of the signer in the MuSig; set to be consistent with the
 *            order of the pubkeys provided to `secp256k1_musig_pubkey_combine`
 *    pubkey: public key that the signer will use for partial signing
 *     nonce: public nonce, must be a valid curvepoint if the signer is `present`
 * nonce_commitment: pre-commitment to the nonce, or all-bits zero if a
 *                   precommitment has not yet been set
 */
typedef struct {
    int present;
    size_t index;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey nonce;
    unsigned char nonce_commitment[32];
} secp256k1_musig_signer_data;

/** Opaque data structure that holds a MuSig partial signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 32 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_musig_partial_signature_serialize` and
 *  `secp256k1_musig_partial_signature_parse` functions.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_musig_partial_signature;

/** Computes a combined public key, hash of keys for use with MuSig, and
 *  initializes an array of signer data structures
 *
 *  Returns: 1 always
 *
 *  Args:        ctx: pointer to a context object initialized for verification (cannot be NULL)
 *           scratch: scratch space used to compute the combined pubkey by multiexponentiation
 *                    (cannot be NULL)
 *  Out: combined_pk: the MuSig-combined public key (cannot be NULL)
 *           pk_hash: if non-NULL, filled with the hash of all input public keys
 *       signer_data: if non-NULL, array of signer data structs to be initialized
 *   In:         pks: input array of public keys
 *                 n: length of the above array(s)
 */
SECP256K1_API int secp256k1_musig_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_pubkey *combined_pk,
    unsigned char *pk_hash,
    secp256k1_musig_signer_data *signer_data,
    const secp256k1_pubkey *pks,
    size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(6);

/** Initializes a signing session for a signer
 *
 *  Args:        ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     session: the session structure to initialize (cannot be NULL)
 *       nonce_commitment: filled with a commitment to the genareted nonce (cannot be NULL)
 *  In:   session_id: a *unique* ID to assign to this session (cannot be NULL)
 *             msg32: the message to be signed (cannot be NULL)
 *       combined_pk: the combined public key of all signers (cannot be NULL)
 *           pk_hash: the hash of the signers' individual keys (cannot be NULL)
 *          my_index: index of this signer in the list of signers' keys
 *           sec_key: the signer's secret key (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_session_initialize(
    const secp256k1_context* ctx,
    secp256k1_musig_session *session,
    unsigned char *nonce_commitment,
    const unsigned char *session_id,
    const unsigned char *msg32,
    const secp256k1_pubkey *combined_pk,
    const unsigned char *pk_hash,
    size_t my_index,
    const unsigned char *sec_key
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(9);

/** Initializes a signing session for a non-signing verifier
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  Out:     session: the session structure to initialize (cannot be NULL)
 *  In:        msg32: the message to be signed (cannot be NULL)
 *       combined_pk: the combined public key of all signers (cannot be NULL)
 *           pk_hash: the hash of the signers' individual keys (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_session_initialize_public(
    const secp256k1_context* ctx,
    secp256k1_musig_session *session,
    const unsigned char *msg32,
    const secp256k1_pubkey *combined_pk,
    const unsigned char *pk_hash
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Returns a public nonce, given a list of signers' data with precommitments
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  Out:       nonce: the nonce (cannot be NULL)
 *  In:      session: the signing session (which must have been initialized for a signer) (cannot be NULL)
 *            signer: an array of signers' data, which must have precommitments (cannot be NULL)
 *                 n: the length of the above array
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_session_public_nonce(
    const secp256k1_context* ctx,
    secp256k1_pubkey *nonce,
    const secp256k1_musig_session *session,
    const secp256k1_musig_signer_data *signer,
    size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Updates a session with the combined nonce of all signers
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  In/Out:  session: session to update (cannot be NULL)
 *  In:       signer: an array of signers' data, which must have nonces (cannot be NULL)
 *                 n: the length of the above array
 */
SECP256K1_API int secp256k1_musig_session_combine_nonces(
    const secp256k1_context* ctx,
    secp256k1_musig_session *session,
    const secp256k1_musig_signer_data *signer,
    size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Updates an array of initialized signer data structs with their nonce precommitments
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  In/Out:   signer: array of signer data structs to update (cannot be NULL)
 *  In:  commitments: array of precommitments (cannot be NULL)
 *                 n: the length of the above arrays
 */
SECP256K1_API int secp256k1_musig_set_nonce_commitments(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *signer,
    const unsigned char *const *commitments,
    size_t n_data
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a MuSig partial signature or adaptor signature
 *
 *  Returns: 1
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 */
SECP256K1_API int secp256k1_musig_partial_signature_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_musig_partial_signature* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse and validate a MuSig partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in32: pointer to the 32-byte signature to be parsed
 *
 * After the call, sig will always be initialized. If parsing failed or the
 * encoded numbers are out of range, signature validation with it is
 * guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_musig_partial_signature_parse(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature* sig,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Checks a signer's public nonce against a precommitment to said nonce, and update data structure if they match
 *
 *  Returns: 1: commitment was valid, data structure updated
 *           0: commitment was invalid, nothing happened
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In/Out: data: pointer to the signer data to update (cannot be NULL)
 *  In:   pubnon: signer's alleged public nonce (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_set_nonce(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *data,
    const secp256k1_pubkey *pubnon
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Produces a partial signature
 *
 *  Returns: 1: partial signature constructed
 *           0: session in incorrect or inconsistent state
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  partial_sig: partial signature (cannot be NULL)
 *  In:       session: active signing session for which the combined nonce has
 *                     been computed (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_session *session
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Checks that an individual partial signature is valid
 *
 * It is not essential to use this function, in the sense that if any partial
 * signatures are invalid, the full signature will also be invalid, so the
 * problem will be caught. But this function allows determining the specific
 * party who produced an invalid signature, so that signing can be restarted
 * without them.
 *
 *  Returns: 1: partial signature was valid
 *           0: invalid signature or bad data
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:   partial_sig: signature to check (cannot be NULL)
 *            session: active session for which the combined nonce has been
 *                     computed (cannot be NULL)
 *             signer: data for the signer who produced this signature (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_session *session,
    const secp256k1_musig_signer_data *signer
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Combines partial signatures
 *
 *  Returns: 1: all partial signatures had valid data. Does NOT mean the resulting signature is valid.
 *           0: some partial signature had s/r out of range
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:          sig: complete signature (cannot be NULL)
 *  In:   partial_sig: array of partial signatures to combine (cannot be NULL)
 *             n_sigs: number of signatures in the above array
 *            session: initialized session for which the combined nonce has been computed (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_combine(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig *sig,
    const secp256k1_musig_partial_signature *partial_sig,
    size_t n_sigs,
    const secp256k1_musig_session *session
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

/** Extracts a public adaptor from an adaptor signature
 *
 *  Returns: 1: adaptor signature was correctly encoded and had nontrivial adaptor
 *           0: invalid adaptor signature or invalid adaptor
 *  Args:         ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:  pub_adaptor: public adaptor (cannot be NULL)
 *  In:   partial_sig: signature to check (cannot be NULL)
 *            session: active session for which the combined nonce has been
 *                     computed (cannot be NULL)
 *             signer: data for the signer who produced this signature (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_adaptor_extract(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pub_adaptor,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_session *session,
    const secp256k1_musig_signer_data *signer
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Converts a partial signature to an adaptor signature by adding a given secret adaptor
 *
 *  Returns: 1: signature and secret adaptor contained valid values
 *           0: otherwise
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  partial_sig: partial signature to produce (cannot be NULL)
 *  In:   adaptor_sig: adaptor signature to tweak with secret adaptor (cannot be NULL)
 *        sec_adaptor: secret adaptor to add to the adaptor signature (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_partial_to_adaptor_sig(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_partial_signature *adaptor_sig,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Converts an adaptor signature to a partial signature by subtracting a given secret adaptor
 *
 *  Returns: 1: signature and secret adaptor contained valid values
 *           0: otherwise
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  partial_sig: partial signature to produce (cannot be NULL)
 *  In:   adaptor_sig: adaptor signature to tweak with secret adaptor (cannot be NULL)
 *        sec_adaptor: secret adaptor to add to the adaptor signature (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_adaptor_to_partial_sig(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_partial_signature *adaptor_sig,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts a secret adaptor from a complete 2-of-2 multisignature, given one
 *  party's partial signature and the other's adaptor signature. This function
 *  will not fail unless given grossly invalid data; if it is merely given signatures
 *  that do not validate, the returned value will be nonsense. It is therefore
 *  important that all data be validated at earlier steps of any protocol that
 *  uses this function.
 *
 *  Returns: 1: signatures contained valid data such that an adaptor could be extracted
 *           0: otherwise
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  sec_adaptor: secret adaptor (cannot be NULL)
 *  In:           sig: complete 2-of-2 signature
 *        partial_sig: partial signature (cannot be NULL)
 *        adaptor_sig: adaptor signature (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_extract_secret_adaptor(
    const secp256k1_context* ctx,
    unsigned char *sec_adaptor,
    const secp256k1_schnorrsig *sig,
    const secp256k1_musig_partial_signature *adaptor_sig,
    const secp256k1_musig_partial_signature *partial_sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#endif
