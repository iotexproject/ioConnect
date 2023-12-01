#ifndef IOTEX_ECDH_H
#define IOTEX_ECDH_H

#include "include/iotex/build_info.h"

#include "include/iotex/ecp.h"

/*
 * IOTEX supports two formats for ECDH contexts (#iotex_ecdh_context
 * defined in `ecdh.h`). For most applications, the choice of format makes
 * no difference, since all library functions can work with either format,
 * except that the new format is incompatible with IOTEX_ECP_RESTARTABLE.

 * The new format used when this option is disabled is smaller
 * (56 bytes on a 32-bit platform). In future versions of the library, it
 * will support alternative implementations of ECDH operations.
 * The new format is incompatible with applications that access
 * context fields directly and with restartable ECP operations.
 */

#if defined(IOTEX_ECP_RESTARTABLE)
#define IOTEX_ECDH_LEGACY_CONTEXT
#else
#undef IOTEX_ECDH_LEGACY_CONTEXT
#endif

#if defined(IOTEX_ECDH_VARIANT_EVEREST_ENABLED)
#undef IOTEX_ECDH_LEGACY_CONTEXT
#include "include/everest/everest.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Defines the source of the imported EC key.
 */
typedef enum
{
    IOTEX_ECDH_OURS,   /**< Our key. */
    IOTEX_ECDH_THEIRS, /**< The key of the peer. */
} iotex_ecdh_side;

#if !defined(IOTEX_ECDH_LEGACY_CONTEXT)
/**
 * Defines the ECDH implementation used.
 *
 * Later versions of the library may add new variants, therefore users should
 * not make any assumptions about them.
 */
typedef enum
{
    IOTEX_ECDH_VARIANT_NONE = 0,   /*!< Implementation not defined. */
    IOTEX_ECDH_VARIANT_IOTEX_2_0,/*!< The default Mbed TLS implementation */
#if defined(IOTEX_ECDH_VARIANT_EVEREST_ENABLED)
    IOTEX_ECDH_VARIANT_EVEREST     /*!< Everest implementation */
#endif
} iotex_ecdh_variant;

/**
 * The context used by the default ECDH implementation.
 *
 * Later versions might change the structure of this context, therefore users
 * should not make any assumptions about the structure of
 * iotex_ecdh_context_mbed.
 */
typedef struct iotex_ecdh_context_mbed
{
    iotex_ecp_group grp;   /*!< The elliptic curve used. */
    iotex_mpi d;           /*!< The private key. */
    iotex_ecp_point Q;     /*!< The public key. */
    iotex_ecp_point Qp;    /*!< The value of the public key of the peer. */
    iotex_mpi z;           /*!< The shared secret. */
#if defined(IOTEX_ECP_RESTARTABLE)
    iotex_ecp_restart_ctx rs; /*!< The restart context for EC computations. */
#endif
} iotex_ecdh_context_mbed;
#endif

/**
 *
 * \warning         Performing multiple operations concurrently on the same
 *                  ECDSA context is not supported; objects of this type
 *                  should not be shared between multiple threads.
 * \brief           The ECDH context structure.
 */
typedef struct iotex_ecdh_context
{
#if defined(IOTEX_ECDH_LEGACY_CONTEXT)
    iotex_ecp_group grp;   /*!< The elliptic curve used. */
    iotex_mpi d;           /*!< The private key. */
    iotex_ecp_point Q;     /*!< The public key. */
    iotex_ecp_point Qp;    /*!< The value of the public key of the peer. */
    iotex_mpi z;           /*!< The shared secret. */
    int point_format;        /*!< The format of point export in TLS messages. */
    iotex_ecp_point Vi;    /*!< The blinding value. */
    iotex_ecp_point Vf;    /*!< The unblinding value. */
    iotex_mpi _d;          /*!< The previous \p d. */
#if defined(IOTEX_ECP_RESTARTABLE)
    int restart_enabled;        /*!< The flag for restartable mode. */
    iotex_ecp_restart_ctx rs; /*!< The restart context for EC computations. */
#endif /* IOTEX_ECP_RESTARTABLE */
#else
    uint8_t point_format;       /*!< The format of point export in TLS messages
                                  as defined in RFC 4492. */
    iotex_ecp_group_id grp_id;/*!< The elliptic curve used. */
    iotex_ecdh_variant var;   /*!< The ECDH implementation/structure used. */
    union
    {
        iotex_ecdh_context_mbed   mbed_ecdh;
#if defined(IOTEX_ECDH_VARIANT_EVEREST_ENABLED)
        iotex_ecdh_context_everest everest_ecdh;
#endif
    } ctx;                      /*!< Implementation-specific context. The
                                  context in use is specified by the \c var
                                  field. */
#if defined(IOTEX_ECP_RESTARTABLE)
    uint8_t restart_enabled;    /*!< The flag for restartable mode. Functions of
                                  an alternative implementation not supporting
                                  restartable mode must return
                                  IOTEX_ERR_PLATFORM_FEATURE_UNSUPPORTED error
                                  if this flag is set. */
#endif /* IOTEX_ECP_RESTARTABLE */
#endif /* IOTEX_ECDH_LEGACY_CONTEXT */
}
iotex_ecdh_context;

/**
 * \brief          Check whether a given group can be used for ECDH.
 *
 * \param gid      The ECP group ID to check.
 *
 * \return         \c 1 if the group can be used, \c 0 otherwise
 */
int iotex_ecdh_can_do( iotex_ecp_group_id gid );

/**
 * \brief           This function generates an ECDH keypair on an elliptic
 *                  curve.
 *
 *                  This function performs the first of two core computations
 *                  implemented during the ECDH key exchange. The second core
 *                  computation is performed by iotex_ecdh_compute_shared().
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  iotex_ecp_load() or iotex_ecp_tls_read_group().
 * \param d         The destination MPI (private key).
 *                  This must be initialized.
 * \param Q         The destination point (public key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c IOTEX_ERR_ECP_XXX or
 *                  \c IOTEX_MPI_XXX error code on failure.
 */
int iotex_ecdh_gen_public( iotex_ecp_group *grp, iotex_mpi *d, iotex_ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief           This function computes the shared secret.
 *
 *                  This function performs the second of two core computations
 *                  implemented during the ECDH key exchange. The first core
 *                  computation is performed by iotex_ecdh_gen_public().
 *
 * \see             ecp.h
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see iotex_ecp_mul().
 *
 * \param grp       The ECP group to use. This must be initialized and have
 *                  domain parameters loaded, for example through
 *                  iotex_ecp_load() or iotex_ecp_tls_read_group().
 * \param z         The destination MPI (shared secret).
 *                  This must be initialized.
 * \param Q         The public key from another party.
 *                  This must be initialized.
 * \param d         Our secret exponent (private key).
 *                  This must be initialized.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't need a
 *                  context argument.
 *
 * \return          \c 0 on success.
 * \return          Another \c IOTEX_ERR_ECP_XXX or
 *                  \c IOTEX_MPI_XXX error code on failure.
 */
int iotex_ecdh_compute_shared( iotex_ecp_group *grp, iotex_mpi *z,
                         const iotex_ecp_point *Q, const iotex_mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

/**
 * \brief           This function initializes an ECDH context.
 *
 * \param ctx       The ECDH context to initialize. This must not be \c NULL.
 */
void iotex_ecdh_init( iotex_ecdh_context *ctx );

/**
 * \brief           This function sets up the ECDH context with the information
 *                  given.
 *
 *                  This function should be called after iotex_ecdh_init() but
 *                  before iotex_ecdh_make_params(). There is no need to call
 *                  this function before iotex_ecdh_read_params().
 *
 *                  This is the first function used by a TLS server for ECDHE
 *                  ciphersuites.
 *
 * \param ctx       The ECDH context to set up. This must be initialized.
 * \param grp_id    The group id of the group to set up the context for.
 *
 * \return          \c 0 on success.
 */
int iotex_ecdh_setup( iotex_ecdh_context *ctx,
                        iotex_ecp_group_id grp_id );

/**
 * \brief           This function frees a context.
 *
 * \param ctx       The context to free. This may be \c NULL, in which
 *                  case this function does nothing. If it is not \c NULL,
 *                  it must point to an initialized ECDH context.
 */
void iotex_ecdh_free( iotex_ecdh_context *ctx );

/**
 * \brief           This function generates an EC key pair and exports its
 *                  in the format used in a TLS ServerKeyExchange handshake
 *                  message.
 *
 *                  This is the second function used by a TLS server for ECDHE
 *                  ciphersuites. (It is called after iotex_ecdh_setup().)
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDH context to use. This must be initialized
 *                  and bound to a group, for example via iotex_ecdh_setup().
 * \param olen      The address at which to store the number of Bytes written.
 * \param buf       The destination buffer. This must be a writable buffer of
 *                  length \p blen Bytes.
 * \param blen      The length of the destination buffer \p buf in Bytes.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c iotex_ecp_set_max_ops().
 * \return          Another \c IOTEX_ERR_ECP_XXX error code on failure.
 */
int iotex_ecdh_make_params( iotex_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

/**
 * \brief           This function parses the ECDHE parameters in a
 *                  TLS ServerKeyExchange handshake message.
 *
 * \note            In a TLS handshake, this is the how the client
 *                  sets up its ECDHE context from the server's public
 *                  ECDHE key material.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDHE context to use. This must be initialized.
 * \param buf       On input, \c *buf must be the start of the input buffer.
 *                  On output, \c *buf is updated to point to the end of the
 *                  data that has been read. On success, this is the first byte
 *                  past the end of the ServerKeyExchange parameters.
 *                  On error, this is the point at which an error has been
 *                  detected, which is usually not useful except to debug
 *                  failures.
 * \param end       The end of the input buffer.
 *
 * \return          \c 0 on success.
 * \return          An \c IOTEX_ERR_ECP_XXX error code on failure.
 *
 */
int iotex_ecdh_read_params( iotex_ecdh_context *ctx,
                              const unsigned char **buf,
                              const unsigned char *end );

/**
 * \brief           This function sets up an ECDH context from an EC key.
 *
 *                  It is used by clients and servers in place of the
 *                  ServerKeyEchange for static ECDH, and imports ECDH
 *                  parameters from the EC key information of a certificate.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDH context to set up. This must be initialized.
 * \param key       The EC key to use. This must be initialized.
 * \param side      Defines the source of the key. Possible values are:
 *                  - #IOTEX_ECDH_OURS: The key is ours.
 *                  - #IOTEX_ECDH_THEIRS: The key is that of the peer.
 *
 * \return          \c 0 on success.
 * \return          Another \c IOTEX_ERR_ECP_XXX error code on failure.
 *
 */
int iotex_ecdh_get_params( iotex_ecdh_context *ctx,
                             const iotex_ecp_keypair *key,
                             iotex_ecdh_side side );

/**
 * \brief           This function generates a public key and exports it
 *                  as a TLS ClientKeyExchange payload.
 *
 *                  This is the second function used by a TLS client for ECDH(E)
 *                  ciphersuites.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECDH context to use. This must be initialized
 *                  and bound to a group, the latter usually by
 *                  iotex_ecdh_read_params().
 * \param olen      The address at which to store the number of Bytes written.
 *                  This must not be \c NULL.
 * \param buf       The destination buffer. This must be a writable buffer
 *                  of length \p blen Bytes.
 * \param blen      The size of the destination buffer \p buf in Bytes.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL in case \p f_rng doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c iotex_ecp_set_max_ops().
 * \return          Another \c IOTEX_ERR_ECP_XXX error code on failure.
 */
int iotex_ecdh_make_public( iotex_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

/**
 * \brief       This function parses and processes the ECDHE payload of a
 *              TLS ClientKeyExchange message.
 *
 *              This is the third function used by a TLS server for ECDH(E)
 *              ciphersuites. (It is called after iotex_ecdh_setup() and
 *              iotex_ecdh_make_params().)
 *
 * \see         ecp.h
 *
 * \param ctx   The ECDH context to use. This must be initialized
 *              and bound to a group, for example via iotex_ecdh_setup().
 * \param buf   The pointer to the ClientKeyExchange payload. This must
 *              be a readable buffer of length \p blen Bytes.
 * \param blen  The length of the input buffer \p buf in Bytes.
 *
 * \return      \c 0 on success.
 * \return      An \c IOTEX_ERR_ECP_XXX error code on failure.
 */
int iotex_ecdh_read_public( iotex_ecdh_context *ctx,
                              const unsigned char *buf, size_t blen );

/**
 * \brief           This function derives and exports the shared secret.
 *
 *                  This is the last function used by both TLS client
 *                  and servers.
 *
 * \note            If \p f_rng is not NULL, it is used to implement
 *                  countermeasures against side-channel attacks.
 *                  For more information, see iotex_ecp_mul().
 *
 * \see             ecp.h

 * \param ctx       The ECDH context to use. This must be initialized
 *                  and have its own private key generated and the peer's
 *                  public key imported.
 * \param olen      The address at which to store the total number of
 *                  Bytes written on success. This must not be \c NULL.
 * \param buf       The buffer to write the generated shared key to. This
 *                  must be a writable buffer of size \p blen Bytes.
 * \param blen      The length of the destination buffer \p buf in Bytes.
 * \param f_rng     The RNG function to use. This must not be \c NULL.
 * \param p_rng     The RNG context. This may be \c NULL if \p f_rng
 *                  doesn't need a context argument.
 *
 * \return          \c 0 on success.
 * \return          #IOTEX_ERR_ECP_IN_PROGRESS if maximum number of
 *                  operations was reached: see \c iotex_ecp_set_max_ops().
 * \return          Another \c IOTEX_ERR_ECP_XXX error code on failure.
 */
int iotex_ecdh_calc_secret( iotex_ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

#if defined(IOTEX_ECP_RESTARTABLE)
/**
 * \brief           This function enables restartable EC computations for this
 *                  context.  (Default: disabled.)
 *
 * \see             \c iotex_ecp_set_max_ops()
 *
 * \note            It is not possible to safely disable restartable
 *                  computations once enabled, except by free-ing the context,
 *                  which cancels possible in-progress operations.
 *
 * \param ctx       The ECDH context to use. This must be initialized.
 */
void iotex_ecdh_enable_restart( iotex_ecdh_context *ctx );
#endif /* IOTEX_ECP_RESTARTABLE */

#ifdef __cplusplus
}
#endif

#endif /* ecdh.h */
