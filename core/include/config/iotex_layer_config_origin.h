/**
 * \file iotex_layer_config.h
 */

/**
 * This is an optional version symbol that enables compatibility handling of
 * config files.
 *
 * It is equal to the #IOTEX_VERSION_NUMBER of the Mbed TLS version that
 * introduced the config format we want to be compatible with.
 */
//#define IOTEX_CONFIG_VERSION 0x03000000

/**
 * \name SECTION: System support
 *
 * This section sets system specific settings.
 * \{
 */

/**
 * \def IOTEX_HAVE_ASM
 *
 * The compiler has support for asm().
 *
 * Requires support for asm() in compiler.
 *
 * Used in:
 *      library/aria.c
 *      library/bn_mul.h
 *
 * Required by:
 *      IOTEX_AESNI_C
 *      IOTEX_PADLOCK_C
 *
 * Comment to disable the use of assembly code.
 */
#define IOTEX_HAVE_ASM

/**
 * \def IOTEX_NO_UDBL_DIVISION
 *
 * The platform lacks support for double-width integer division (64-bit
 * division on a 32-bit platform, 128-bit division on a 64-bit platform).
 *
 * Used in:
 *      include/mbedtls/bignum.h
 *      library/bignum.c
 *
 * The bignum code uses double-width division to speed up some operations.
 * Double-width division is often implemented in software that needs to
 * be linked with the program. The presence of a double-width integer
 * type is usually detected automatically through preprocessor macros,
 * but the automatic detection cannot know whether the code needs to
 * and can be linked with an implementation of division for that type.
 * By default division is assumed to be usable if the type is present.
 * Uncomment this option to prevent the use of double-width division.
 *
 * Note that division for the native integer type is always required.
 * Furthermore, a 64-bit type is always required even on a 32-bit
 * platform, but it need not support multiplication or division. In some
 * cases it is also desirable to disable some double-width operations. For
 * example, if double-width division is implemented in software, disabling
 * it can reduce code size in some embedded targets.
 */
//#define IOTEX_NO_UDBL_DIVISION

/**
 * \def IOTEX_NO_64BIT_MULTIPLICATION
 *
 * The platform lacks support for 32x32 -> 64-bit multiplication.
 *
 * Used in:
 *      library/poly1305.c
 *
 * Some parts of the library may use multiplication of two unsigned 32-bit
 * operands with a 64-bit result in order to speed up computations. On some
 * platforms, this is not available in hardware and has to be implemented in
 * software, usually in a library provided by the toolchain.
 *
 * Sometimes it is not desirable to have to link to that library. This option
 * removes the dependency of that library on platforms that lack a hardware
 * 64-bit multiplier by embedding a software implementation in Mbed TLS.
 *
 * Note that depending on the compiler, this may decrease performance compared
 * to using the library function provided by the toolchain.
 */
//#define IOTEX_NO_64BIT_MULTIPLICATION

/**
 * \def IOTEX_HAVE_SSE2
 *
 * CPU supports SSE2 instruction set.
 *
 * Uncomment if the CPU supports SSE2 (IA-32 specific).
 */
//#define IOTEX_HAVE_SSE2

/**
 * \def IOTEX_HAVE_TIME
 *
 * System has time.h and time().
 * The time does not need to be correct, only time differences are used,
 * by contrast with IOTEX_HAVE_TIME_DATE
 *
 * Defining IOTEX_HAVE_TIME allows you to specify IOETX_PLATFORM_TIME_ALT,
 * IOTEX_PLATFORM_TIME_MACRO, IOEX_PLATFORM_TIME_TYPE_MACRO and
 * IOEX_PLATFORM_STD_TIME.
 *
 * Comment if your system does not support time functions.
 *
 * \note If IOTEX_TIMING_C is set - to enable the semi-portable timing
 *       interface - timing.c will include time.h on suitable platforms
 *       regardless of the setting of IOTEX_HAVE_TIME, unless
 *       IOTEX_TIMING_ALT is used. See timing.c for more information.
 */
//#define IOTEX_HAVE_TIME

/**
 * \def IOTEX_HAVE_TIME_DATE
 *
 * System has time.h, time(), and an implementation for
 * iotex_platform_gmtime_r() (see below).
 * The time needs to be correct (not necessarily very accurate, but at least
 * the date should be correct). This is used to verify the validity period of
 * X.509 certificates.
 *
 * Comment if your system does not have a correct clock.
 *
 * \note iotex_platform_gmtime_r() is an abstraction in platform_util.h that
 * behaves similarly to the gmtime_r() function from the C standard. Refer to
 * the documentation for iotex_platform_gmtime_r() for more information.
 *
 * \note It is possible to configure an implementation for
 * iotex_platform_gmtime_r() at compile-time by using the macro
 * IOTEX_PLATFORM_GMTIME_R_ALT.
 */
//#define IOTEX_HAVE_TIME_DATE

/**
 * \def IOTEX_PLATFORM_MEMORY
 *
 * Enable the memory allocation layer.
 *
 * By default mbed TLS uses the system-provided calloc() and free().
 * This allows different allocators (self-implemented or provided) to be
 * provided to the platform abstraction layer.
 *
 * Enabling IOTEX_PLATFORM_MEMORY without the
 * IOTEX_PLATFORM_{FREE,CALLOC}_MACROs will provide
 * "iotex_platform_set_calloc_free()" allowing you to set an alternative calloc() and
 * free() function pointer at runtime.
 *
 * Enabling IOTEX_PLATFORM_MEMORY and specifying
 * IOTEX_PLATFORM_{CALLOC,FREE}_MACROs will allow you to specify the
 * alternate function at compile time.
 *
 * Requires: IOTEX_PLATFORM_C
 *
 * Enable this layer to allow use of alternative memory allocators.
 */
//#define IOTEX_PLATFORM_MEMORY

/**
 * \def IOTEX_PLATFORM_NO_STD_FUNCTIONS
 *
 * Do not assign standard functions in the platform layer (e.g. calloc() to
 * IOTEX_PLATFORM_STD_CALLOC and printf() to IOTEX_PLATFORM_STD_PRINTF)
 *
 * This makes sure there are no linking errors on platforms that do not support
 * these functions. You will HAVE to provide alternatives, either at runtime
 * via the platform_set_xxx() functions or at compile time by setting
 * the IOTEX_PLATFORM_STD_XXX defines, or enabling a
 * IOTEX_PLATFORM_XXX_MACRO.
 *
 * Requires: IOTEX_PLATFORM_C
 *
 * Uncomment to prevent default assignment of standard functions in the
 * platform layer.
 */
//#define IOTEX_PLATFORM_NO_STD_FUNCTIONS

/**
 * \def IOTEX_PLATFORM_EXIT_ALT
 *
 * IOTEX_PLATFORM_XXX_ALT: Uncomment a macro to let mbed TLS support the
 * function in the platform abstraction layer.
 *
 * Example: In case you uncomment IOTEX_PLATFORM_PRINTF_ALT, mbed TLS will
 * provide a function "iotex_platform_set_printf()" that allows you to set an
 * alternative printf function pointer.
 *
 * All these define require IOTEX_PLATFORM_C to be defined!
 *
 * \note IOTEX_PLATFORM_SNPRINTF_ALT is required on Windows;
 * it will be enabled automatically by check_config.h
 *
 * \warning IOTEX_PLATFORM_XXX_ALT cannot be defined at the same time as
 * IOTEX_PLATFORM_XXX_MACRO!
 *
 * Requires: IOTEX_PLATFORM_TIME_ALT requires IOTEX_HAVE_TIME
 *
 * Uncomment a macro to enable alternate implementation of specific base
 * platform function
 */
//#define IOTEX_PLATFORM_SETBUF_ALT
//#define IOTEX_PLATFORM_EXIT_ALT
//#define IOTEX_PLATFORM_TIME_ALT
//#define IOTEX_PLATFORM_FPRINTF_ALT
//#define IOTEX_PLATFORM_PRINTF_ALT
//#define IOTEX_PLATFORM_SNPRINTF_ALT
//#define IOTEX_PLATFORM_VSNPRINTF_ALT
//#define IOTEX_PLATFORM_NV_SEED_ALT
//#define IOTEX_PLATFORM_SETUP_TEARDOWN_ALT

/**
 * \def IOTEX_DEPRECATED_WARNING
 *
 * Mark deprecated functions and features so that they generate a warning if
 * used. Functionality deprecated in one version will usually be removed in the
 * next version. You can enable this to help you prepare the transition to a
 * new major version by making sure your code is not using this functionality.
 *
 * This only works with GCC and Clang. With other compilers, you may want to
 * use IOTEX_DEPRECATED_REMOVED
 *
 * Uncomment to get warnings on using deprecated functions and features.
 */
//#define IOTEX_DEPRECATED_WARNING

/**
 * \def IOTEX_DEPRECATED_REMOVED
 *
 * Remove deprecated functions and features so that they generate an error if
 * used. Functionality deprecated in one version will usually be removed in the
 * next version. You can enable this to help you prepare the transition to a
 * new major version by making sure your code is not using this functionality.
 *
 * Uncomment to get errors on using deprecated functions and features.
 */
//#define IOTEX_DEPRECATED_REMOVED

/** \} name SECTION: System support */

/**
 * \name SECTION: mbed TLS feature support
 *
 * This section sets support for features that are or are not needed
 * within the modules that are enabled.
 * \{
 */

/**
 * \def IOTEX_TIMING_ALT
 *
 * Uncomment to provide your own alternate implementation for
 * iotex_timing_get_timer(), iotex_set_alarm(), iotex_set/get_delay()
 *
 * Only works if you have IOTEX_TIMING_C enabled.
 *
 * You will need to provide a header "timing_alt.h" and an implementation at
 * compile time.
 */
//#define IOTEX_TIMING_ALT

/**
 * \def IOTEX_AES_ALT
 *
 * IOTEX__MODULE_NAME__ALT: Uncomment a macro to let mbed TLS use your
 * alternate core implementation of a symmetric crypto, an arithmetic or hash
 * module (e.g. platform specific assembly optimized implementations). Keep
 * in mind that the function prototypes should remain the same.
 *
 * This replaces the whole module. If you only want to replace one of the
 * functions, use one of the IOTEX__FUNCTION_NAME__ALT flags.
 *
 * Example: In case you uncomment IOTEX_AES_ALT, mbed TLS will no longer
 * provide the "struct iotex_aes_context" definition and omit the base
 * function declarations and implementations. "aes_alt.h" will be included from
 * "aes.h" to include the new function definitions.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * module.
 *
 * \warning   MD5, DES and SHA-1 are considered weak and their
 *            use constitutes a security risk. If possible, we recommend
 *            avoiding dependencies on them, and considering stronger message
 *            digests and ciphers instead.
 *
 */
//#define IOTEX_AES_ALT
//#define IOTEX_ARIA_ALT
//#define IOTEX_CAMELLIA_ALT
//#define IOTEX_CCM_ALT
//#define IOTEX_CHACHA20_ALT
//#define IOTEX_CHACHAPOLY_ALT
//#define IOTEX_CMAC_ALT
//#define IOTEX_DES_ALT
//#define IOTEX_DHM_ALT
//#define IOTEX_ECJPAKE_ALT
//#define IOTEX_GCM_ALT
//#define IOTEX_NIST_KW_ALT
//#define IOTEX_MD5_ALT
//#define IOTEX_POLY1305_ALT
//#define IOTEX_RIPEMD160_ALT
//#define IOTEX_RSA_ALT
//#define IOTEX_SHA1_ALT
//#define IOTEX_SHA256_ALT
//#define IOTEX_SHA512_ALT

/*
 * When replacing the elliptic curve module, please consider, that it is
 * implemented with two .c files:
 *      - ecp.c
 *      - ecp_curves.c
 * You can replace them very much like all the other IOTEX__MODULE_NAME__ALT
 * macros as described above. The only difference is that you have to make sure
 * that you provide functionality for both .c files.
 */
//#define IOTEX_ECP_ALT

/**
 * \def IOTEX_SHA256_PROCESS_ALT
 *
 * IOTEX__FUNCTION_NAME__ALT: Uncomment a macro to let mbed TLS use you
 * alternate core implementation of symmetric crypto or hash function. Keep in
 * mind that function prototypes should remain the same.
 *
 * This replaces only one function. The header file from mbed TLS is still
 * used, in contrast to the IOTEX__MODULE_NAME__ALT flags.
 *
 * Example: In case you uncomment IOTEX_SHA256_PROCESS_ALT, mbed TLS will
 * no longer provide the iotex_sha1_process() function, but it will still provide
 * the other function (using your iotex_sha1_process() function) and the definition
 * of iotex_sha1_context, so your implementation of iotex_sha1_process must be compatible
 * with this definition.
 *
 * \note If you use the AES_xxx_ALT macros, then it is recommended to also set
 *       IOTEX_AES_ROM_TABLES in order to help the linker garbage-collect the AES
 *       tables.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * function.
 *
 * \warning   MD5, DES and SHA-1 are considered weak and their use
 *            constitutes a security risk. If possible, we recommend avoiding
 *            dependencies on them, and considering stronger message digests
 *            and ciphers instead.
 *
 * \warning   If both IOTEX_ECDSA_SIGN_ALT and IOTEX_ECDSA_DETERMINISTIC are
 *            enabled, then the deterministic ECDH signature functions pass the
 *            the static HMAC-DRBG as RNG to iotex_ecdsa_sign(). Therefore
 *            alternative implementations should use the RNG only for generating
 *            the ephemeral key and nothing else. If this is not possible, then
 *            IOTEX_ECDSA_DETERMINISTIC should be disabled and an alternative
 *            implementation should be provided for iotex_ecdsa_sign_det_ext().
 *
 */
//#define IOTEX_MD5_PROCESS_ALT
//#define IOTEX_RIPEMD160_PROCESS_ALT
//#define IOTEX_SHA1_PROCESS_ALT
//#define IOTEX_SHA256_PROCESS_ALT
//#define IOTEX_SHA512_PROCESS_ALT
//#define IOTEX_DES_SETKEY_ALT
//#define IOTEX_DES_CRYPT_ECB_ALT
//#define IOTEX_DES3_CRYPT_ECB_ALT
//#define IOTEX_AES_SETKEY_ENC_ALT
//#define IOTEX_AES_SETKEY_DEC_ALT
//#define IOTEX_AES_ENCRYPT_ALT
//#define IOTEX_AES_DECRYPT_ALT
//#define IOTEX_ECDH_GEN_PUBLIC_ALT
//#define IOTEX_ECDH_COMPUTE_SHARED_ALT
//#define IOTEX_ECDSA_VERIFY_ALT
//#define IOTEX_ECDSA_SIGN_ALT
//#define IOTEX_ECDSA_GENKEY_ALT

/**
 * \def IOTEX_ECP_INTERNAL_ALT
 *
 * Expose a part of the internal interface of the Elliptic Curve Point module.
 *
 * IOTEX_ECP__FUNCTION_NAME__ALT: Uncomment a macro to let mbed TLS use your
 * alternative core implementation of elliptic curve arithmetic. Keep in mind
 * that function prototypes should remain the same.
 *
 * This partially replaces one function. The header file from mbed TLS is still
 * used, in contrast to the IOTEX_ECP_ALT flag. The original implementation
 * is still present and it is used for group structures not supported by the
 * alternative.
 *
 * The original implementation can in addition be removed by setting the
 * IOTEX_ECP_NO_FALLBACK option, in which case any function for which the
 * corresponding IOTEX_ECP__FUNCTION_NAME__ALT macro is defined will not be
 * able to fallback to curves not supported by the alternative implementation.
 *
 * Any of these options become available by defining IOTEX_ECP_INTERNAL_ALT
 * and implementing the following functions:
 *      unsigned char iotex_internal_ecp_grp_capable(
 *          const iotex_ecp_group *grp )
 *      int  iotex_internal_ecp_init( const iotex_ecp_group *grp )
 *      void iotex_internal_ecp_free( const iotex_ecp_group *grp )
 * The iotex_internal_ecp_grp_capable function should return 1 if the
 * replacement functions implement arithmetic for the given group and 0
 * otherwise.
 * The functions iotex_internal_ecp_init and iotex_internal_ecp_free are
 * called before and after each point operation and provide an opportunity to
 * implement optimized set up and tear down instructions.
 *
 * Example: In case you set IOTEX_ECP_INTERNAL_ALT and
 * IOTEX_ECP_DOUBLE_JAC_ALT, mbed TLS will still provide the ecp_double_jac()
 * function, but will use your iotex_internal_ecp_double_jac() if the group
 * for the operation is supported by your implementation (i.e. your
 * iotex_internal_ecp_grp_capable() function returns 1 for this group). If the
 * group is not supported by your implementation, then the original mbed TLS
 * implementation of ecp_double_jac() is used instead, unless this fallback
 * behaviour is disabled by setting IOTEX_ECP_NO_FALLBACK (in which case
 * ecp_double_jac() will return IOTEX_ERR_ECP_FEATURE_UNAVAILABLE).
 *
 * The function prototypes and the definition of iotex_ecp_group and
 * iotex_ecp_point will not change based on IOTEX_ECP_INTERNAL_ALT, so your
 * implementation of iotex_internal_ecp__function_name__ must be compatible
 * with their definitions.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * function.
 */
/* Required for all the functions in this section */
//#define IOTEX_ECP_INTERNAL_ALT
/* Turn off software fallback for curves not supported in hardware */
//#define IOTEX_ECP_NO_FALLBACK
/* Support for Weierstrass curves with Jacobi representation */
//#define IOTEX_ECP_RANDOMIZE_JAC_ALT
//#define IOTEX_ECP_ADD_MIXED_ALT
//#define IOTEX_ECP_DOUBLE_JAC_ALT
//#define IOTEX_ECP_NORMALIZE_JAC_MANY_ALT
//#define IOTEX_ECP_NORMALIZE_JAC_ALT
/* Support for curves with Montgomery arithmetic */
//#define IOTEX_ECP_DOUBLE_ADD_MXZ_ALT
//#define IOTEX_ECP_RANDOMIZE_MXZ_ALT
//#define IOTEX_ECP_NORMALIZE_MXZ_ALT

/**
 * \def IOTEX_ENTROPY_HARDWARE_ALT
 *
 * Uncomment this macro to let mbed TLS use your own implementation of a
 * hardware entropy collector.
 *
 * Your function must be called \c iotex_hardware_poll(), have the same
 * prototype as declared in library/entropy_poll.h, and accept NULL as first
 * argument.
 *
 * Uncomment to use your own hardware entropy collector.
 */
//#define IOTEX_ENTROPY_HARDWARE_ALT

/**
 * \def IOTEX_AES_ROM_TABLES
 *
 * Use precomputed AES tables stored in ROM.
 *
 * Uncomment this macro to use precomputed AES tables stored in ROM.
 * Comment this macro to generate AES tables in RAM at runtime.
 *
 * Tradeoff: Using precomputed ROM tables reduces RAM usage by ~8kb
 * (or ~2kb if \c IOTEX_AES_FEWER_TABLES is used) and reduces the
 * initialization time before the first AES operation can be performed.
 * It comes at the cost of additional ~8kb ROM use (resp. ~2kb if \c
 * IOTEX_AES_FEWER_TABLES below is used), and potentially degraded
 * performance if ROM access is slower than RAM access.
 *
 * This option is independent of \c IOTEX_AES_FEWER_TABLES.
 *
 */
//#define IOTEX_AES_ROM_TABLES

/**
 * \def IOTEX_AES_FEWER_TABLES
 *
 * Use less ROM/RAM for AES tables.
 *
 * Uncommenting this macro omits 75% of the AES tables from
 * ROM / RAM (depending on the value of \c IOTEX_AES_ROM_TABLES)
 * by computing their values on the fly during operations
 * (the tables are entry-wise rotations of one another).
 *
 * Tradeoff: Uncommenting this reduces the RAM / ROM footprint
 * by ~6kb but at the cost of more arithmetic operations during
 * runtime. Specifically, one has to compare 4 accesses within
 * different tables to 4 accesses with additional arithmetic
 * operations within the same table. The performance gain/loss
 * depends on the system and memory details.
 *
 * This option is independent of \c IOTEX_AES_ROM_TABLES.
 *
 */
//#define IOTEX_AES_FEWER_TABLES

/**
 * \def IOTEX_CAMELLIA_SMALL_MEMORY
 *
 * Use less ROM for the Camellia implementation (saves about 768 bytes).
 *
 * Uncomment this macro to use less memory for Camellia.
 */
//#define IOTEX_CAMELLIA_SMALL_MEMORY

/**
 * \def IOTEX_CHECK_RETURN_WARNING
 *
 * If this macro is defined, emit a compile-time warning if application code
 * calls a function without checking its return value, but the return value
 * should generally be checked in portable applications.
 *
 * This is only supported on platforms where #IOTEX_CHECK_RETURN is
 * implemented. Otherwise this option has no effect.
 *
 * Uncomment to get warnings on using fallible functions without checking
 * their return value.
 *
 * \note  This feature is a work in progress.
 *        Warnings will be added to more functions in the future.
 *
 * \note  A few functions are considered critical, and ignoring the return
 *        value of these functions will trigger a warning even if this
 *        macro is not defined. To completely disable return value check
 *        warnings, define #IOTEX_CHECK_RETURN with an empty expansion.
 */
//#define IOTEX_CHECK_RETURN_WARNING

/**
 * \def IOTEX_CIPHER_MODE_CBC
 *
 * Enable Cipher Block Chaining mode (CBC) for symmetric ciphers.
 */
#define IOTEX_CIPHER_MODE_CBC

/**
 * \def IOTEX_CIPHER_MODE_CFB
 *
 * Enable Cipher Feedback mode (CFB) for symmetric ciphers.
 */
//#define IOTEX_CIPHER_MODE_CFB

/**
 * \def IOTEX_CIPHER_MODE_CTR
 *
 * Enable Counter Block Cipher mode (CTR) for symmetric ciphers.
 */
#define IOTEX_CIPHER_MODE_CTR

/**
 * \def IOTEX_CIPHER_MODE_OFB
 *
 * Enable Output Feedback mode (OFB) for symmetric ciphers.
 */
//#define IOTEX_CIPHER_MODE_OFB

/**
 * \def IOTEX_CIPHER_MODE_XTS
 *
 * Enable Xor-encrypt-xor with ciphertext stealing mode (XTS) for AES.
 */
//#define IOTEX_CIPHER_MODE_XTS

/**
 * \def IOTEX_CIPHER_NULL_CIPHER
 *
 * Enable NULL cipher.
 * Warning: Only do so when you know what you are doing. This allows for
 * encryption or channels without any security!
 *
 * To enable the following ciphersuites:
 *      IOTEX_TLS_ECDH_ECDSA_WITH_NULL_SHA
 *      IOTEX_TLS_ECDH_RSA_WITH_NULL_SHA
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_NULL_SHA
 *      IOTEX_TLS_ECDHE_RSA_WITH_NULL_SHA
 *      IOTEX_TLS_ECDHE_PSK_WITH_NULL_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_NULL_SHA256
 *      IOTEX_TLS_ECDHE_PSK_WITH_NULL_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_NULL_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_NULL_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_NULL_SHA
 *      IOTEX_TLS_RSA_WITH_NULL_SHA256
 *      IOTEX_TLS_RSA_WITH_NULL_SHA
 *      IOTEX_TLS_RSA_WITH_NULL_MD5
 *      IOTEX_TLS_RSA_PSK_WITH_NULL_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_NULL_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_NULL_SHA
 *      IOTEX_TLS_PSK_WITH_NULL_SHA384
 *      IOTEX_TLS_PSK_WITH_NULL_SHA256
 *      IOTEX_TLS_PSK_WITH_NULL_SHA
 *
 * Uncomment this macro to enable the NULL cipher and ciphersuites
 */
//#define IOTEX_CIPHER_NULL_CIPHER

/**
 * \def IOTEX_CIPHER_PADDING_PKCS7
 *
 * IOTEX_CIPHER_PADDING_XXX: Uncomment or comment macros to add support for
 * specific padding modes in the cipher layer with cipher modes that support
 * padding (e.g. CBC)
 *
 * If you disable all padding modes, only full blocks can be used with CBC.
 *
 * Enable padding modes in the cipher layer.
 */
#define IOTEX_CIPHER_PADDING_PKCS7
#define IOTEX_CIPHER_PADDING_ONE_AND_ZEROS
#define IOTEX_CIPHER_PADDING_ZEROS_AND_LEN
#define IOTEX_CIPHER_PADDING_ZEROS

/** \def IOTEX_CTR_DRBG_USE_128_BIT_KEY
 *
 * Uncomment this macro to use a 128-bit key in the CTR_DRBG module.
 * By default, CTR_DRBG uses a 256-bit key.
 */
//#define IOTEX_CTR_DRBG_USE_128_BIT_KEY

/**
 * \def IOTEX_ECP_DP_SECP192R1_ENABLED
 *
 * IOTEX_ECP_XXXX_ENABLED: Enables specific curves within the Elliptic Curve
 * module.  By default all supported curves are enabled.
 *
 * Comment macros to disable the curve and functions for it
 */
/* Short Weierstrass curves (supporting ECP, ECDH, ECDSA) */
#define IOTEX_ECP_DP_SECP192R1_ENABLED
#define IOTEX_ECP_DP_SECP224R1_ENABLED
#define IOTEX_ECP_DP_SECP256R1_ENABLED
#define IOTEX_ECP_DP_SECP384R1_ENABLED
#define IOTEX_ECP_DP_SECP521R1_ENABLED
#define IOTEX_ECP_DP_SECP192K1_ENABLED
#define IOTEX_ECP_DP_SECP224K1_ENABLED
#define IOTEX_ECP_DP_SECP256K1_ENABLED
//#define IOTEX_ECP_DP_BP256R1_ENABLED
//#define IOTEX_ECP_DP_BP384R1_ENABLED
//#define IOTEX_ECP_DP_BP512R1_ENABLED
/* Montgomery curves (supporting ECP) */
#define IOTEX_ECP_DP_CURVE25519_ENABLED
//#define IOTEX_ECP_DP_CURVE448_ENABLED

/**
 * \def IOTEX_ECP_NIST_OPTIM
 *
 * Enable specific 'modulo p' routines for each NIST prime.
 * Depending on the prime and architecture, makes operations 4 to 8 times
 * faster on the corresponding curve.
 *
 * Comment this macro to disable NIST curves optimisation.
 */
#define IOTEX_ECP_NIST_OPTIM

/**
 * \def IOTEX_ECP_RESTARTABLE
 *
 * Enable "non-blocking" ECC operations that can return early and be resumed.
 *
 * This allows various functions to pause by returning
 * #IOTEX_ERR_ECP_IN_PROGRESS (or, for functions in the SSL module,
 * #IOTEX_ERR_SSL_CRYPTO_IN_PROGRESS) and then be called later again in
 * order to further progress and eventually complete their operation. This is
 * controlled through iotex_ecp_set_max_ops() which limits the maximum
 * number of ECC operations a function may perform before pausing; see
 * iotex_ecp_set_max_ops() for more information.
 *
 * This is useful in non-threaded environments if you want to avoid blocking
 * for too long on ECC (and, hence, X.509 or SSL/TLS) operations.
 *
 * Uncomment this macro to enable restartable ECC computations.
 *
 * \note  This option only works with the default software implementation of
 *        elliptic curve functionality. It is incompatible with
 *        IOTEX_ECP_ALT, IOTEX_ECDH_XXX_ALT, IOTEX_ECDSA_XXX_ALT.
 */
//#define IOTEX_ECP_RESTARTABLE

/**
 * \def IOTEX_ECDSA_DETERMINISTIC
 *
 * Enable deterministic ECDSA (RFC 6979).
 * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
 * may result in a compromise of the long-term signing key. This is avoided by
 * the deterministic variant.
 *
 * Requires: IOTEX_HMAC_DRBG_C, IOTEX_ECDSA_C
 *
 * Comment this macro to disable deterministic ECDSA.
 */
//#define IOTEX_ECDSA_DETERMINISTIC

/**
 * \def IOTEX_KEY_EXCHANGE_PSK_ENABLED
 *
 * Enable the PSK based ciphersuite modes in SSL / TLS.
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_PSK_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_PSK_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
#define IOTEX_KEY_EXCHANGE_PSK_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_DHE_PSK_ENABLED
 *
 * Enable the DHE-PSK based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_DHM_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *
 * \warning    Using DHE constitutes a security risk as it
 *             is not possible to validate custom DH parameters.
 *             If possible, it is recommended users should consider
 *             preferring other methods of key exchange.
 *             See dhm.h for more details.
 *
 */
//#define IOTEX_KEY_EXCHANGE_DHE_PSK_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_ECDHE_PSK_ENABLED
 *
 * Enable the ECDHE-PSK based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_ECDH_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
//#define IOTEX_KEY_EXCHANGE_ECDHE_PSK_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_RSA_PSK_ENABLED
 *
 * Enable the RSA-PSK based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_RSA_C, IOTEX_PKCS1_V15,
 *           IOTEX_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
//#define IOTEX_KEY_EXCHANGE_RSA_PSK_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_RSA_ENABLED
 *
 * Enable the RSA-only based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_RSA_C, IOTEX_PKCS1_V15,
 *           IOTEX_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_RSA_WITH_AES_256_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      IOTEX_TLS_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
 */
//#define IOTEX_KEY_EXCHANGE_RSA_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_DHE_RSA_ENABLED
 *
 * Enable the DHE-RSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_DHM_C, IOTEX_RSA_C, IOTEX_PKCS1_V15,
 *           IOTEX_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      IOTEX_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
 *
 * \warning    Using DHE constitutes a security risk as it
 *             is not possible to validate custom DH parameters.
 *             If possible, it is recommended users should consider
 *             preferring other methods of key exchange.
 *             See dhm.h for more details.
 *
 */
//#define IOTEX_KEY_EXCHANGE_DHE_RSA_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_ECDHE_RSA_ENABLED
 *
 * Enable the ECDHE-RSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_ECDH_C, IOTEX_RSA_C, IOTEX_PKCS1_V15,
 *           IOTEX_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 */
//#define IOTEX_KEY_EXCHANGE_ECDHE_RSA_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
 *
 * Enable the ECDHE-ECDSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_ECDH_C, IOTEX_ECDSA_C, IOTEX_X509_CRT_PARSE_C,
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 */
//#define IOTEX_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
 *
 * Enable the ECDH-ECDSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_ECDH_C, IOTEX_ECDSA_C, IOTEX_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 */
//#define IOTEX_KEY_EXCHANGE_ECDH_ECDSA_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_ECDH_RSA_ENABLED
 *
 * Enable the ECDH-RSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: IOTEX_ECDH_C, IOTEX_RSA_C, IOTEX_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
 */
//#define IOTEX_KEY_EXCHANGE_ECDH_RSA_ENABLED

/**
 * \def IOTEX_KEY_EXCHANGE_ECJPAKE_ENABLED
 *
 * Enable the ECJPAKE based ciphersuite modes in SSL / TLS.
 *
 * \warning This is currently experimental. EC J-PAKE support is based on the
 * Thread v1.0.0 specification; incompatible changes to the specification
 * might still happen. For this reason, this is disabled by default.
 *
 * Requires: IOTEX_ECJPAKE_C
 *           IOTEX_SHA256_C
 *           IOTEX_ECP_DP_SECP256R1_ENABLED
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECJPAKE_WITH_AES_128_CCM_8
 */
//#define IOTEX_KEY_EXCHANGE_ECJPAKE_ENABLED

/**
 * \def IOTEX_PK_PARSE_EC_EXTENDED
 *
 * Enhance support for reading EC keys using variants of SEC1 not allowed by
 * RFC 5915 and RFC 5480.
 *
 * Currently this means parsing the SpecifiedECDomain choice of EC
 * parameters (only known groups are supported, not arbitrary domains, to
 * avoid validation issues).
 *
 * Disable if you only need to support RFC 5915 + 5480 key formats.
 */
#define IOTEX_PK_PARSE_EC_EXTENDED

/**
 * \def IOTEX_ERROR_STRERROR_DUMMY
 *
 * Enable a dummy error function to make use of iotex_strerror() in
 * third party libraries easier when IOTEX_ERROR_C is disabled
 * (no effect when IOTEX_ERROR_C is enabled).
 *
 * You can safely disable this if IOTEX_ERROR_C is enabled, or if you're
 * not using iotex_strerror() or error_strerror() in your application.
 *
 * Disable if you run into name conflicts and want to really remove the
 * iotex_strerror()
 */
#define IOTEX_ERROR_STRERROR_DUMMY

/**
 * \def IOTEX_GENPRIME
 *
 * Enable the prime-number generation code.
 *
 * Requires: IOTEX_BIGNUM_C
 */
#define IOTEX_GENPRIME

/**
 * \def IOTEX_FS_IO
 *
 * Enable functions that use the filesystem.
 */
//#define IOTEX_FS_IO

/**
 * \def IOTEX_NO_DEFAULT_ENTROPY_SOURCES
 *
 * Do not add default entropy sources in iotex_entropy_init().
 *
 * This is useful to have more control over the added entropy sources in an
 * application.
 *
 * Uncomment this macro to prevent loading of default entropy functions.
 */
//#define IOTEX_NO_DEFAULT_ENTROPY_SOURCES

/**
 * \def IOTEX_NO_PLATFORM_ENTROPY
 *
 * Do not use built-in platform entropy functions.
 * This is useful if your platform does not support
 * standards like the /dev/urandom or Windows CryptoAPI.
 *
 * Uncomment this macro to disable the built-in platform entropy functions.
 */
#define IOTEX_NO_PLATFORM_ENTROPY

/**
 * \def IOTEX_ENTROPY_FORCE_SHA256
 *
 * Force the entropy accumulator to use a SHA-256 accumulator instead of the
 * default SHA-512 based one (if both are available).
 *
 * Requires: IOTEX_SHA256_C
 *
 * On 32-bit systems SHA-256 can be much faster than SHA-512. Use this option
 * if you have performance concerns.
 *
 * This option is only useful if both IOTEX_SHA256_C and
 * IOTEX_SHA512_C are defined. Otherwise the available hash module is used.
 */
//#define IOTEX_ENTROPY_FORCE_SHA256

/**
 * \def IOTEX_ENTROPY_NV_SEED
 *
 * Enable the non-volatile (NV) seed file-based entropy source.
 * (Also enables the NV seed read/write functions in the platform layer)
 *
 * This is crucial (if not required) on systems that do not have a
 * cryptographic entropy source (in hardware or kernel) available.
 *
 * Requires: IOTEX_ENTROPY_C, IOTEX_PLATFORM_C
 *
 * \note The read/write functions that are used by the entropy source are
 *       determined in the platform layer, and can be modified at runtime and/or
 *       compile-time depending on the flags (IOTEX_PLATFORM_NV_SEED_*) used.
 *
 * \note If you use the default implementation functions that read a seedfile
 *       with regular fopen(), please make sure you make a seedfile with the
 *       proper name (defined in IOTEX_PLATFORM_STD_NV_SEED_FILE) and at
 *       least IOTEX_ENTROPY_BLOCK_SIZE bytes in size that can be read from
 *       and written to or you will get an entropy source error! The default
 *       implementation will only use the first IOTEX_ENTROPY_BLOCK_SIZE
 *       bytes from the file.
 *
 * \note The entropy collector will write to the seed file before entropy is
 *       given to an external source, to update it.
 */
//#define IOTEX_ENTROPY_NV_SEED

/* IOTEX_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
 *
 * Enable key identifiers that encode a key owner identifier.
 *
 * The owner of a key is identified by a value of type ::iotex_key_owner_id_t
 * which is currently hard-coded to be int32_t.
 *
 * Note that this option is meant for internal use only and may be removed
 * without notice.
 */
//#define IOTEX_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

/**
 * \def IOTEX_MEMORY_DEBUG
 *
 * Enable debugging of buffer allocator memory issues. Automatically prints
 * (to stderr) all (fatal) messages on memory allocation issues. Enables
 * function for 'debug output' of allocated memory.
 *
 * Requires: IOTEX_MEMORY_BUFFER_ALLOC_C
 *
 * Uncomment this macro to let the buffer allocator print out error messages.
 */
//#define IOTEX_MEMORY_DEBUG

/**
 * \def IOTEX_MEMORY_BACKTRACE
 *
 * Include backtrace information with each allocated block.
 *
 * Requires: IOTEX_MEMORY_BUFFER_ALLOC_C
 *           GLIBC-compatible backtrace() an backtrace_symbols() support
 *
 * Uncomment this macro to include backtrace information
 */
//#define IOTEX_MEMORY_BACKTRACE

/**
 * \def IOTEX_PK_RSA_ALT_SUPPORT
 *
 * Support external private RSA keys (eg from a HSM) in the PK layer.
 *
 * Comment this macro to disable support for external private RSA keys.
 */
//#define IOTEX_PK_RSA_ALT_SUPPORT

/**
 * \def IOTEX_PKCS1_V15
 *
 * Enable support for PKCS#1 v1.5 encoding.
 *
 * Requires: IOTEX_MD_C, IOTEX_RSA_C
 *
 * This enables support for PKCS#1 v1.5 operations.
 */
//#define IOTEX_PKCS1_V15

/**
 * \def IOTEX_PKCS1_V21
 *
 * Enable support for PKCS#1 v2.1 encoding.
 *
 * Requires: IOTEX_MD_C, IOTEX_RSA_C
 *
 * This enables support for RSAES-OAEP and RSASSA-PSS operations.
 */
#define IOTEX_PKCS1_V21

/** \def IOTEX_PSA_CRYPTO_BUILTIN_KEYS
 *
 * Enable support for platform built-in keys. If you enable this feature,
 * you must implement the function iotex_psa_platform_get_builtin_key().
 * See the documentation of that function for more information.
 *
 * Built-in keys are typically derived from a hardware unique key or
 * stored in a secure element.
 *
 * Requires: IOTEX_PSA_CRYPTO_C.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
//#define IOTEX_PSA_CRYPTO_BUILTIN_KEYS

/** \def IOTEX_PSA_CRYPTO_CLIENT
 *
 * Enable support for PSA crypto client.
 *
 * \note This option allows to include the code necessary for a PSA
 *       crypto client when the PSA crypto implementation is not included in
 *       the library (IOTEX_PSA_CRYPTO_C disabled). The code included is the
 *       code to set and get PSA key attributes.
 *       The development of PSA drivers partially relying on the library to
 *       fulfill the hardware gaps is another possible usage of this option.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
//#define IOTEX_PSA_CRYPTO_CLIENT

/** \def IOTEX_PSA_CRYPTO_DRIVERS
 *
 * Enable support for the experimental PSA crypto driver interface.
 *
 * Requires: IOTEX_PSA_CRYPTO_C
 *
 * \warning This interface is experimental. We intend to maintain backward
 *          compatibility with application code that relies on drivers,
 *          but the driver interfaces may change without notice.
 */
//#define IOTEX_PSA_CRYPTO_DRIVERS

/** \def IOTEX_PSA_CRYPTO_EXTERNAL_RNG
 *
 * Make the PSA Crypto module use an external random generator provided
 * by a driver, instead of IOTEX's entropy and DRBG modules.
 *
 * \note This random generator must deliver random numbers with cryptographic
 *       quality and high performance. It must supply unpredictable numbers
 *       with a uniform distribution. The implementation of this function
 *       is responsible for ensuring that the random generator is seeded
 *       with sufficient entropy. If you have a hardware TRNG which is slow
 *       or delivers non-uniform output, declare it as an entropy source
 *       with iotex_entropy_add_source() instead of enabling this option.
 *
 * If you enable this option, you must configure the type
 * ::iotex_psa_external_random_context_t in psa/crypto_platform.h
 * and define a function called iotex_psa_external_get_random()
 * with the following prototype:
 * ```
 * psa_status_t iotex_psa_external_get_random(
 *     iotex_psa_external_random_context_t *context,
 *     uint8_t *output, size_t output_size, size_t *output_length);
 * );
 * ```
 * The \c context value is initialized to 0 before the first call.
 * The function must fill the \c output buffer with \p output_size bytes
 * of random data and set \c *output_length to \p output_size.
 *
 * Requires: IOTEX_PSA_CRYPTO_C
 *
 * \warning If you enable this option, code that uses the PSA cryptography
 *          interface will not use any of the entropy sources set up for
 *          the entropy module, nor the NV seed that IOTEX_ENTROPY_NV_SEED
 *          enables.
 *
 * \note This option is experimental and may be removed without notice.
 */
#define IOTEX_PSA_CRYPTO_EXTERNAL_RNG

/**
 * \def IOTEX_PSA_CRYPTO_SPM
 *
 * When IOTEX_PSA_CRYPTO_SPM is defined, the code is built for SPM (Secure
 * Partition Manager) integration which separates the code into two parts: a
 * NSPE (Non-Secure Process Environment) and an SPE (Secure Process
 * Environment).
 *
 * Module:  library/psa_crypto.c
 * Requires: IOTEX_PSA_CRYPTO_C
 *
 */
//#define IOTEX_PSA_CRYPTO_SPM

/**
 * \def IOTEX_PSA_INJECT_ENTROPY
 *
 * Enable support for entropy injection at first boot. This feature is
 * required on systems that do not have a built-in entropy source (TRNG).
 * This feature is currently not supported on systems that have a built-in
 * entropy source.
 *
 * Requires: IOTEX_PSA_CRYPTO_STORAGE_C, IOTEX_ENTROPY_NV_SEED
 *
 */
//#define IOTEX_PSA_INJECT_ENTROPY

/**
 * \def IOTEX_RSA_NO_CRT
 *
 * Do not use the Chinese Remainder Theorem
 * for the RSA private operation.
 *
 * Uncomment this macro to disable the use of CRT in RSA.
 *
 */
//#define IOTEX_RSA_NO_CRT

/**
 * \def IOTEX_SELF_TEST
 *
 * Enable the checkup functions (*_self_test).
 */
//#define IOTEX_SELF_TEST

/**
 * \def IOTEX_SHA256_SMALLER
 *
 * Enable an implementation of SHA-256 that has lower ROM footprint but also
 * lower performance.
 *
 * The default implementation is meant to be a reasonable compromise between
 * performance and size. This version optimizes more aggressively for size at
 * the expense of performance. Eg on Cortex-M4 it reduces the size of
 * iotex_sha256_process() from ~2KB to ~0.5KB for a performance hit of about
 * 30%.
 *
 * Uncomment to enable the smaller implementation of SHA256.
 */
//#define IOTEX_SHA256_SMALLER

/**
 * \def IOTEX_SHA512_SMALLER
 *
 * Enable an implementation of SHA-512 that has lower ROM footprint but also
 * lower performance.
 *
 * Uncomment to enable the smaller implementation of SHA512.
 */
//#define IOTEX_SHA512_SMALLER

/**
 * \def IOTEX_SSL_ALL_ALERT_MESSAGES
 *
 * Enable sending of alert messages in case of encountered errors as per RFC.
 * If you choose not to send the alert messages, mbed TLS can still communicate
 * with other servers, only debugging of failures is harder.
 *
 * The advantage of not sending alert messages, is that no information is given
 * about reasons for failures thus preventing adversaries of gaining intel.
 *
 * Enable sending of all alert messages
 */
//#define IOTEX_SSL_ALL_ALERT_MESSAGES

/**
 * \def IOTEX_SSL_DTLS_CONNECTION_ID
 *
 * Enable support for the DTLS Connection ID extension
 * (version draft-ietf-tls-dtls-connection-id-05,
 * https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-05)
 * which allows to identify DTLS connections across changes
 * in the underlying transport.
 *
 * Setting this option enables the SSL APIs `iotex_ssl_set_cid()`,
 * iotex_ssl_get_own_cid()`, `iotex_ssl_get_peer_cid()` and
 * `iotex_ssl_conf_cid()`. See the corresponding documentation for
 * more information.
 *
 * \warning The Connection ID extension is still in draft state.
 *          We make no stability promises for the availability
 *          or the shape of the API controlled by this option.
 *
 * The maximum lengths of outgoing and incoming CIDs can be configured
 * through the options
 * - IOTEX_SSL_CID_OUT_LEN_MAX
 * - IOTEX_SSL_CID_IN_LEN_MAX.
 *
 * Requires: IOTEX_SSL_PROTO_DTLS
 *
 * Uncomment to enable the Connection ID extension.
 */
//#define IOTEX_SSL_DTLS_CONNECTION_ID

/**
 * \def IOTEX_SSL_ASYNC_PRIVATE
 *
 * Enable asynchronous external private key operations in SSL. This allows
 * you to configure an SSL connection to call an external cryptographic
 * module to perform private key operations instead of performing the
 * operation inside the library.
 *
 */
//#define IOTEX_SSL_ASYNC_PRIVATE

/**
 * \def IOTEX_SSL_CONTEXT_SERIALIZATION
 *
 * Enable serialization of the TLS context structures, through use of the
 * functions iotex_ssl_context_save() and iotex_ssl_context_load().
 *
 * This pair of functions allows one side of a connection to serialize the
 * context associated with the connection, then free or re-use that context
 * while the serialized state is persisted elsewhere, and finally deserialize
 * that state to a live context for resuming read/write operations on the
 * connection. From a protocol perspective, the state of the connection is
 * unaffected, in particular this is entirely transparent to the peer.
 *
 * Note: this is distinct from TLS session resumption, which is part of the
 * protocol and fully visible by the peer. TLS session resumption enables
 * establishing new connections associated to a saved session with shorter,
 * lighter handshakes, while context serialization is a local optimization in
 * handling a single, potentially long-lived connection.
 *
 * Enabling these APIs makes some SSL structures larger, as 64 extra bytes are
 * saved after the handshake to allow for more efficient serialization, so if
 * you don't need this feature you'll save RAM by disabling it.
 *
 * Comment to disable the context serialization APIs.
 */
//#define IOTEX_SSL_CONTEXT_SERIALIZATION

/**
 * \def IOTEX_SSL_DEBUG_ALL
 *
 * Enable the debug messages in SSL module for all issues.
 * Debug messages have been disabled in some places to prevent timing
 * attacks due to (unbalanced) debugging function calls.
 *
 * If you need all error reporting you should enable this during debugging,
 * but remove this for production servers that should log as well.
 *
 * Uncomment this macro to report all debug messages on errors introducing
 * a timing side-channel.
 *
 */
//#define IOTEX_SSL_DEBUG_ALL

/** \def IOTEX_SSL_ENCRYPT_THEN_MAC
 *
 * Enable support for Encrypt-then-MAC, RFC 7366.
 *
 * This allows peers that both support it to use a more robust protection for
 * ciphersuites using CBC, providing deep resistance against timing attacks
 * on the padding or underlying cipher.
 *
 * This only affects CBC ciphersuites, and is useless if none is defined.
 *
 * Requires: IOTEX_SSL_PROTO_TLS1_2
 *
 * Comment this macro to disable support for Encrypt-then-MAC
 */
//#define IOTEX_SSL_ENCRYPT_THEN_MAC

/** \def IOTEX_SSL_EXTENDED_MASTER_SECRET
 *
 * Enable support for RFC 7627: Session Hash and Extended Master Secret
 * Extension.
 *
 * This was introduced as "the proper fix" to the Triple Handshake family of
 * attacks, but it is recommended to always use it (even if you disable
 * renegotiation), since it actually fixes a more fundamental issue in the
 * original SSL/TLS design, and has implications beyond Triple Handshake.
 *
 * Requires: IOTEX_SSL_PROTO_TLS1_2
 *
 * Comment this macro to disable support for Extended Master Secret.
 */
//#define IOTEX_SSL_EXTENDED_MASTER_SECRET

/**
 * \def IOTEX_SSL_KEEP_PEER_CERTIFICATE
 *
 * This option controls the availability of the API iotex_ssl_get_peer_cert()
 * giving access to the peer's certificate after completion of the handshake.
 *
 * Unless you need iotex_ssl_peer_cert() in your application, it is
 * recommended to disable this option for reduced RAM usage.
 *
 * \note If this option is disabled, iotex_ssl_get_peer_cert() is still
 *       defined, but always returns \c NULL.
 *
 * \note This option has no influence on the protection against the
 *       triple handshake attack. Even if it is disabled, Mbed TLS will
 *       still ensure that certificates do not change during renegotiation,
 *       for example by keeping a hash of the peer's certificate.
 *
 * \note This option is required if IOTEX_SSL_PROTO_TLS1_3 is set.
 *
 * Comment this macro to disable storing the peer's certificate
 * after the handshake.
 */
#define IOTEX_SSL_KEEP_PEER_CERTIFICATE

/**
 * \def IOTEX_SSL_RENEGOTIATION
 *
 * Enable support for TLS renegotiation.
 *
 * The two main uses of renegotiation are (1) refresh keys on long-lived
 * connections and (2) client authentication after the initial handshake.
 * If you don't need renegotiation, it's probably better to disable it, since
 * it has been associated with security issues in the past and is easy to
 * misuse/misunderstand.
 *
 * Comment this to disable support for renegotiation.
 *
 * \note   Even if this option is disabled, both client and server are aware
 *         of the Renegotiation Indication Extension (RFC 5746) used to
 *         prevent the SSL renegotiation attack (see RFC 5746 Sect. 1).
 *         (See \c iotex_ssl_conf_legacy_renegotiation for the
 *          configuration of this extension).
 *
 */
//#define IOTEX_SSL_RENEGOTIATION

/**
 * \def IOTEX_SSL_MAX_FRAGMENT_LENGTH
 *
 * Enable support for RFC 6066 max_fragment_length extension in SSL.
 *
 * Comment this macro to disable support for the max_fragment_length extension
 */
#define IOTEX_SSL_MAX_FRAGMENT_LENGTH

/**
 * \def IOTEX_SSL_PROTO_TLS1_2
 *
 * Enable support for TLS 1.2 (and DTLS 1.2 if DTLS is enabled).
 *
 * Requires: IOTEX_SHA1_C or IOTEX_SHA256_C or IOTEX_SHA512_C
 *           (Depends on ciphersuites)
 *
 * Comment this macro to disable support for TLS 1.2 / DTLS 1.2
 */
//#define IOTEX_SSL_PROTO_TLS1_2

/**
 * \def IOTEX_SSL_PROTO_TLS1_3
 *
 * Enable support for TLS 1.3.
 *
 * \note The support for TLS 1.3 is not comprehensive yet, in particular
 *       pre-shared keys are not supported.
 *       See docs/architecture/tls13-support.md for a description of the TLS
 *       1.3 support that this option enables.
 *
 * Requires: IOTEX_SSL_KEEP_PEER_CERTIFICATE
 * Requires: IOTEX_PSA_CRYPTO_C
 *
 * Note: even though TLS 1.3 depends on PSA Crypto, if you want it to only use
 * PSA for all crypto operations, you need to also enable
 * IOTEX_USE_PSA_CRYPTO; otherwise X.509 operations, and functions that are
 * common with TLS 1.2 (record protection, running handshake hash) will still
 * use non-PSA crypto.
 *
 * Uncomment this macro to enable the support for TLS 1.3.
 */
//#define IOTEX_SSL_PROTO_TLS1_3

/**
 * \def IOTEX_SSL_TLS1_3_COMPATIBILITY_MODE
 *
 * Enable TLS 1.3 middlebox compatibility mode.
 *
 * As specified in Section D.4 of RFC 8446, TLS 1.3 offers a compatibility
 * mode to make a TLS 1.3 connection more likely to pass through middle boxes
 * expecting TLS 1.2 traffic.
 *
 * Turning on the compatibility mode comes at the cost of a few added bytes
 * on the wire, but it doesn't affect compatibility with TLS 1.3 implementations
 * that don't use it. Therefore, unless transmission bandwidth is critical and
 * you know that middlebox compatibility issues won't occur, it is therefore
 * recommended to set this option.
 *
 * Comment to disable compatibility mode for TLS 1.3. If
 * IOTEX_SSL_PROTO_TLS1_3 is not enabled, this option does not have any
 * effect on the build.
 *
 */
//#define IOTEX_SSL_TLS1_3_COMPATIBILITY_MODE

/**
 * \def IOTEX_SSL_PROTO_DTLS
 *
 * Enable support for DTLS (all available versions).
 *
 * Enable this and IOTEX_SSL_PROTO_TLS1_2 to enable DTLS 1.2.
 *
 * Requires: IOTEX_SSL_PROTO_TLS1_2
 *
 * Comment this macro to disable support for DTLS
 */
//#define IOTEX_SSL_PROTO_DTLS

/**
 * \def IOTEX_SSL_ALPN
 *
 * Enable support for RFC 7301 Application Layer Protocol Negotiation.
 *
 * Comment this macro to disable support for ALPN.
 */
//#define IOTEX_SSL_ALPN

/**
 * \def IOTEX_SSL_DTLS_ANTI_REPLAY
 *
 * Enable support for the anti-replay mechanism in DTLS.
 *
 * Requires: IOTEX_SSL_TLS_C
 *           IOTEX_SSL_PROTO_DTLS
 *
 * \warning Disabling this is often a security risk!
 * See iotex_ssl_conf_dtls_anti_replay() for details.
 *
 * Comment this to disable anti-replay in DTLS.
 */
//#define IOTEX_SSL_DTLS_ANTI_REPLAY

/**
 * \def IOTEX_SSL_DTLS_HELLO_VERIFY
 *
 * Enable support for HelloVerifyRequest on DTLS servers.
 *
 * This feature is highly recommended to prevent DTLS servers being used as
 * amplifiers in DoS attacks against other hosts. It should always be enabled
 * unless you know for sure amplification cannot be a problem in the
 * environment in which your server operates.
 *
 * \warning Disabling this can be a security risk! (see above)
 *
 * Requires: IOTEX_SSL_PROTO_DTLS
 *
 * Comment this to disable support for HelloVerifyRequest.
 */
//#define IOTEX_SSL_DTLS_HELLO_VERIFY

/**
 * \def IOTEX_SSL_DTLS_SRTP
 *
 * Enable support for negotiation of DTLS-SRTP (RFC 5764)
 * through the use_srtp extension.
 *
 * \note This feature provides the minimum functionality required
 * to negotiate the use of DTLS-SRTP and to allow the derivation of
 * the associated SRTP packet protection key material.
 * In particular, the SRTP packet protection itself, as well as the
 * demultiplexing of RTP and DTLS packets at the datagram layer
 * (see Section 5 of RFC 5764), are not handled by this feature.
 * Instead, after successful completion of a handshake negotiating
 * the use of DTLS-SRTP, the extended key exporter API
 * iotex_ssl_conf_export_keys_cb() should be used to implement
 * the key exporter described in Section 4.2 of RFC 5764 and RFC 5705
 * (this is implemented in the SSL example programs).
 * The resulting key should then be passed to an SRTP stack.
 *
 * Setting this option enables the runtime API
 * iotex_ssl_conf_dtls_srtp_protection_profiles()
 * through which the supported DTLS-SRTP protection
 * profiles can be configured. You must call this API at
 * runtime if you wish to negotiate the use of DTLS-SRTP.
 *
 * Requires: IOTEX_SSL_PROTO_DTLS
 *
 * Uncomment this to enable support for use_srtp extension.
 */
//#define IOTEX_SSL_DTLS_SRTP

/**
 * \def IOTEX_SSL_DTLS_CLIENT_PORT_REUSE
 *
 * Enable server-side support for clients that reconnect from the same port.
 *
 * Some clients unexpectedly close the connection and try to reconnect using the
 * same source port. This needs special support from the server to handle the
 * new connection securely, as described in section 4.2.8 of RFC 6347. This
 * flag enables that support.
 *
 * Requires: IOTEX_SSL_DTLS_HELLO_VERIFY
 *
 * Comment this to disable support for clients reusing the source port.
 */
//#define IOTEX_SSL_DTLS_CLIENT_PORT_REUSE

/**
 * \def IOTEX_SSL_SESSION_TICKETS
 *
 * Enable support for RFC 5077 session tickets in SSL.
 * Client-side, provides full support for session tickets (maintenance of a
 * session store remains the responsibility of the application, though).
 * Server-side, you also need to provide callbacks for writing and parsing
 * tickets, including authenticated encryption and key management. Example
 * callbacks are provided by IOTEX_SSL_TICKET_C.
 *
 * Comment this macro to disable support for SSL session tickets
 */
//#define IOTEX_SSL_SESSION_TICKETS

/**
 * \def IOTEX_SSL_SERVER_NAME_INDICATION
 *
 * Enable support for RFC 6066 server name indication (SNI) in SSL.
 *
 * Requires: IOTEX_X509_CRT_PARSE_C
 *
 * Comment this macro to disable support for server name indication in SSL
 */
//#define IOTEX_SSL_SERVER_NAME_INDICATION

/**
 * \def IOTEX_SSL_VARIABLE_BUFFER_LENGTH
 *
 * When this option is enabled, the SSL buffer will be resized automatically
 * based on the negotiated maximum fragment length in each direction.
 *
 * Requires: IOTEX_SSL_MAX_FRAGMENT_LENGTH
 */
//#define IOTEX_SSL_VARIABLE_BUFFER_LENGTH

/**
 * \def IOTEX_TEST_CONSTANT_FLOW_MEMSAN
 *
 * Enable testing of the constant-flow nature of some sensitive functions with
 * clang's MemorySanitizer. This causes some existing tests to also test
 * this non-functional property of the code under test.
 *
 * This setting requires compiling with clang -fsanitize=memory. The test
 * suites can then be run normally.
 *
 * \warning This macro is only used for extended testing; it is not considered
 * part of the library's API, so it may change or disappear at any time.
 *
 * Uncomment to enable testing of the constant-flow nature of selected code.
 */
//#define IOTEX_TEST_CONSTANT_FLOW_MEMSAN

/**
 * \def IOTEX_TEST_CONSTANT_FLOW_VALGRIND
 *
 * Enable testing of the constant-flow nature of some sensitive functions with
 * valgrind's memcheck tool. This causes some existing tests to also test
 * this non-functional property of the code under test.
 *
 * This setting requires valgrind headers for building, and is only useful for
 * testing if the tests suites are run with valgrind's memcheck. This can be
 * done for an individual test suite with 'valgrind ./test_suite_xxx', or when
 * using CMake, this can be done for all test suites with 'make memcheck'.
 *
 * \warning This macro is only used for extended testing; it is not considered
 * part of the library's API, so it may change or disappear at any time.
 *
 * Uncomment to enable testing of the constant-flow nature of selected code.
 */
//#define IOTEX_TEST_CONSTANT_FLOW_VALGRIND

/**
 * \def IOTEX_TEST_HOOKS
 *
 * Enable features for invasive testing such as introspection functions and
 * hooks for fault injection. This enables additional unit tests.
 *
 * Merely enabling this feature should not change the behavior of the product.
 * It only adds new code, and new branching points where the default behavior
 * is the same as when this feature is disabled.
 * However, this feature increases the attack surface: there is an added
 * risk of vulnerabilities, and more gadgets that can make exploits easier.
 * Therefore this feature must never be enabled in production.
 *
 * See `docs/architecture/testing/mbed-crypto-invasive-testing.md` for more
 * information.
 *
 * Uncomment to enable invasive tests.
 */
//#define IOTEX_TEST_HOOKS

/**
 * \def IOTEX_THREADING_ALT
 *
 * Provide your own alternate threading implementation.
 *
 * Requires: IOTEX_THREADING_C
 *
 * Uncomment this to allow your own alternate threading implementation.
 */
//#define IOTEX_THREADING_ALT

/**
 * \def IOTEX_THREADING_PTHREAD
 *
 * Enable the pthread wrapper layer for the threading layer.
 *
 * Requires: IOTEX_THREADING_C
 *
 * Uncomment this to enable pthread mutexes.
 */
//#define IOTEX_THREADING_PTHREAD

/**
 * \def IOTEX_USE_PSA_CRYPTO
 *
 * Make the X.509 and TLS library use PSA for cryptographic operations, and
 * enable new APIs for using keys handled by PSA Crypto.
 *
 * \note Development of this option is currently in progress, and parts of Mbed
 * TLS's X.509 and TLS modules are not ported to PSA yet. However, these parts
 * will still continue to work as usual, so enabling this option should not
 * break backwards compatibility.
 *
 * \note See docs/use-psa-crypto.md for a complete description of what this
 * option currently does, and of parts that are not affected by it so far.
 *
 * \warning If you enable this option, you need to call `psa_crypto_init()`
 * before calling any function from the SSL/TLS, X.509 or PK modules.
 *
 * Requires: IOTEX_PSA_CRYPTO_C.
 * Conflicts with: IOTEX_ECP_RESTARTABLE
 *
 * Uncomment this to enable internal use of PSA Crypto and new associated APIs.
 */
//#define IOTEX_USE_PSA_CRYPTO

/**
 * \def IOTEX_PSA_CRYPTO_CONFIG
 *
 * This setting allows support for cryptographic mechanisms through the PSA
 * API to be configured separately from support through the mbedtls API.
 *
 * When this option is disabled, the PSA API exposes the cryptographic
 * mechanisms that can be implemented on top of the `iotex_xxx` API
 * configured with `IOTEX_XXX` symbols.
 *
 * When this option is enabled, the PSA API exposes the cryptographic
 * mechanisms requested by the `PSA_WANT_XXX` symbols defined in
 * include/psa/crypto_config.h. The corresponding `IOTEX_XXX` settings are
 * automatically enabled if required (i.e. if no PSA driver provides the
 * mechanism). You may still freely enable additional `IOTEX_XXX` symbols
 * in iotex_config.h.
 *
 * If the symbol #IOTEX_PSA_CRYPTO_CONFIG_FILE is defined, it specifies
 * an alternative header to include instead of include/psa/crypto_config.h.
 *
 * This feature is still experimental and is not ready for production since
 * it is not completed.
 */
//#define IOTEX_PSA_CRYPTO_CONFIG

/**
 * \def IOTEX_VERSION_FEATURES
 *
 * Allow run-time checking of compile-time enabled features. Thus allowing users
 * to check at run-time if the library is for instance compiled with threading
 * support via iotex_version_check_feature().
 *
 * Requires: IOTEX_VERSION_C
 *
 * Comment this to disable run-time checking and save ROM space
 */
#define IOTEX_VERSION_FEATURES

/**
 * \def IOTEX_X509_TRUSTED_CERTIFICATE_CALLBACK
 *
 * If set, this enables the X.509 API `iotex_x509_crt_verify_with_ca_cb()`
 * and the SSL API `iotex_ssl_conf_ca_cb()` which allow users to configure
 * the set of trusted certificates through a callback instead of a linked
 * list.
 *
 * This is useful for example in environments where a large number of trusted
 * certificates is present and storing them in a linked list isn't efficient
 * enough, or when the set of trusted certificates changes frequently.
 *
 * See the documentation of `iotex_x509_crt_verify_with_ca_cb()` and
 * `iotex_ssl_conf_ca_cb()` for more information.
 *
 * Uncomment to enable trusted certificate callbacks.
 */
//#define IOTEX_X509_TRUSTED_CERTIFICATE_CALLBACK

/**
 * \def IOTEX_X509_REMOVE_INFO
 *
 * Disable iotex_x509_*_info() and related APIs.
 *
 * Uncomment to omit iotex_x509_*_info(), as well as iotex_debug_print_crt()
 * and other functions/constants only used by these functions, thus reducing
 * the code footprint by several KB.
 */
//#define IOTEX_X509_REMOVE_INFO

/**
 * \def IOTEX_X509_RSASSA_PSS_SUPPORT
 *
 * Enable parsing and verification of X.509 certificates, CRLs and CSRS
 * signed with RSASSA-PSS (aka PKCS#1 v2.1).
 *
 * Comment this macro to disallow using RSASSA-PSS in certificates.
 */
//#define IOTEX_X509_RSASSA_PSS_SUPPORT
/** \} name SECTION: mbed TLS feature support */

/**
 * \name SECTION: mbed TLS modules
 *
 * This section enables or disables entire modules in mbed TLS
 * \{
 */

/**
 * \def IOTEX_AESNI_C
 *
 * Enable AES-NI support on x86-64.
 *
 * Module:  library/aesni.c
 * Caller:  library/aes.c
 *
 * Requires: IOTEX_HAVE_ASM
 *
 * This modules adds support for the AES-NI instructions on x86-64
 */
//#define IOTEX_AESNI_C

/**
 * \def IOTEX_AES_C
 *
 * Enable the AES block cipher.
 *
 * Module:  library/aes.c
 * Caller:  library/cipher.c
 *          library/pem.c
 *          library/ctr_drbg.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_RSA_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_RSA_WITH_AES_256_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_RSA_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_RSA_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_AES_128_CBC_SHA
 *      IOTEX_TLS_PSK_WITH_AES_256_GCM_SHA384
 *      IOTEX_TLS_PSK_WITH_AES_256_CBC_SHA384
 *      IOTEX_TLS_PSK_WITH_AES_256_CBC_SHA
 *      IOTEX_TLS_PSK_WITH_AES_128_GCM_SHA256
 *      IOTEX_TLS_PSK_WITH_AES_128_CBC_SHA256
 *      IOTEX_TLS_PSK_WITH_AES_128_CBC_SHA
 *
 * PEM_PARSE uses AES for decrypting encrypted keys.
 */
#define IOTEX_AES_C

/**
 * \def IOTEX_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  library/asn1.c
 * Caller:  library/x509.c
 *          library/dhm.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/pkparse.c
 */
#define IOTEX_ASN1_PARSE_C

/**
 * \def IOTEX_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  library/asn1write.c
 * Caller:  library/ecdsa.c
 *          library/pkwrite.c
 *          library/x509_create.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 */
#define IOTEX_ASN1_WRITE_C

/**
 * \def IOTEX_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  library/base64.c
 * Caller:  library/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define IOTEX_BASE64_C

/**
 * \def IOTEX_BIGNUM_C
 *
 * Enable the multi-precision integer library.
 *
 * Module:  library/bignum.c
 * Caller:  library/dhm.c
 *          library/ecp.c
 *          library/ecdsa.c
 *          library/rsa.c
 *          library/rsa_alt_helpers.c
 *          library/ssl_tls.c
 *
 * This module is required for RSA, DHM and ECC (ECDH, ECDSA) support.
 */
#define IOTEX_BIGNUM_C

/**
 * \def IOTEX_CAMELLIA_C
 *
 * Enable the Camellia block cipher.
 *
 * Module:  library/camellia.c
 * Caller:  library/cipher.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      IOTEX_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
//#define IOTEX_CAMELLIA_C

/**
 * \def IOTEX_ARIA_C
 *
 * Enable the ARIA block cipher.
 *
 * Module:  library/aria.c
 * Caller:  library/cipher.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *
 *      IOTEX_TLS_RSA_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_RSA_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_RSA_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_RSA_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_PSK_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_PSK_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
 *      IOTEX_TLS_PSK_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_PSK_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256
 *      IOTEX_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384
 *      IOTEX_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
 *      IOTEX_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
 */
//#define IOTEX_ARIA_C

/**
 * \def IOTEX_CCM_C
 *
 * Enable the Counter with CBC-MAC (CCM) mode for 128-bit block cipher.
 *
 * Module:  library/ccm.c
 *
 * Requires: IOTEX_CIPHER_C, IOTEX_AES_C or IOTEX_CAMELLIA_C or
 *                             IOTEX_ARIA_C
 *
 * This module enables the AES-CCM ciphersuites, if other requisites are
 * enabled as well.
 */
//#define IOTEX_CCM_C

/**
 * \def IOTEX_CHACHA20_C
 *
 * Enable the ChaCha20 stream cipher.
 *
 * Module:  library/chacha20.c
 */
//#define IOTEX_CHACHA20_C

/**
 * \def IOTEX_CHACHAPOLY_C
 *
 * Enable the ChaCha20-Poly1305 AEAD algorithm.
 *
 * Module:  library/chachapoly.c
 *
 * This module requires: IOTEX_CHACHA20_C, IOTEX_POLY1305_C
 */
//#define IOTEX_CHACHAPOLY_C

/**
 * \def IOTEX_CIPHER_C
 *
 * Enable the generic cipher layer.
 *
 * Module:  library/cipher.c
 * Caller:  library/ccm.c
 *          library/cmac.c
 *          library/gcm.c
 *          library/nist_kw.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/psa_crypto_aead.c
 *          library/psa_crypto_mac.c
 *          library/ssl_ciphersuites.c
 *          library/ssl_msg.c
 *          library/ssl_ticket.c (unless IOTEX_USE_PSA_CRYPTO is enabled)
 *
 * Uncomment to enable generic cipher wrappers.
 */
#define IOTEX_CIPHER_C

/**
 * \def IOTEX_CMAC_C
 *
 * Enable the CMAC (Cipher-based Message Authentication Code) mode for block
 * ciphers.
 *
 * \note When #IOTEX_CMAC_ALT is active, meaning that the underlying
 *       implementation of the CMAC algorithm is provided by an alternate
 *       implementation, that alternate implementation may opt to not support
 *       AES-192 or 3DES as underlying block ciphers for the CMAC operation.
 *
 * Module:  library/cmac.c
 *
 * Requires: IOTEX_CIPHER_C, IOTEX_AES_C or IOTEX_DES_C
 *
 */
#define IOTEX_CMAC_C

/**
 * \def IOTEX_CTR_DRBG_C
 *
 * Enable the CTR_DRBG AES-based random generator.
 * The CTR_DRBG generator uses AES-256 by default.
 * To use AES-128 instead, enable \c IOTEX_CTR_DRBG_USE_128_BIT_KEY above.
 *
 * \note To achieve a 256-bit security strength with CTR_DRBG,
 *       you must use AES-256 *and* use sufficient entropy.
 *       See ctr_drbg.h for more details.
 *
 * Module:  library/ctr_drbg.c
 * Caller:
 *
 * Requires: IOTEX_AES_C
 *
 * This module provides the CTR_DRBG AES random number generator.
 */
//#define IOTEX_CTR_DRBG_C

/**
 * \def IOTEX_DEBUG_C
 *
 * Enable the debug functions.
 *
 * Module:  library/debug.c
 * Caller:  library/ssl_msg.c
 *          library/ssl_tls.c
 *          library/ssl_tls12_*.c
 *          library/ssl_tls13_*.c
 *
 * This module provides debugging functions.
 */
//#define IOTEX_DEBUG_C

/**
 * \def IOTEX_DES_C
 *
 * Enable the DES block cipher.
 *
 * Module:  library/des.c
 * Caller:  library/pem.c
 *          library/cipher.c
 *
 * PEM_PARSE uses DES/3DES for decrypting encrypted keys.
 *
 * \warning   DES is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 */
//#define IOTEX_DES_C

/**
 * \def IOTEX_DHM_C
 *
 * Enable the Diffie-Hellman-Merkle module.
 *
 * Module:  library/dhm.c
 * Caller:  library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      DHE-RSA, DHE-PSK
 *
 * \warning    Using DHE constitutes a security risk as it
 *             is not possible to validate custom DH parameters.
 *             If possible, it is recommended users should consider
 *             preferring other methods of key exchange.
 *             See dhm.h for more details.
 *
 */
#define IOTEX_DHM_C

/**
 * \def IOTEX_ECDH_C
 *
 * Enable the elliptic curve Diffie-Hellman library.
 *
 * Module:  library/ecdh.c
 * Caller:  library/psa_crypto.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA, ECDHE-RSA, DHE-PSK
 *
 * Requires: IOTEX_ECP_C
 */
#define IOTEX_ECDH_C

/**
 * \def IOTEX_ECDSA_C
 *
 * Enable the elliptic curve DSA library.
 *
 * Module:  library/ecdsa.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA
 *
 * Requires: IOTEX_ECP_C, IOTEX_ASN1_WRITE_C, IOTEX_ASN1_PARSE_C,
 *           and at least one IOTEX_ECP_DP_XXX_ENABLED for a
 *           short Weierstrass curve.
 */
#define IOTEX_ECDSA_C

/**
 * \def IOTEX_ECJPAKE_C
 *
 * Enable the elliptic curve J-PAKE library.
 *
 * \note EC J-PAKE support is based on the Thread v1.0.0 specification.
 *       It has not been reviewed for compliance with newer standards such as
 *       Thread v1.1 or RFC 8236.
 *
 * Module:  library/ecjpake.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECJPAKE
 *
 * Requires: IOTEX_ECP_C, IOTEX_MD_C
 */
//#define IOTEX_ECJPAKE_C

/**
 * \def IOTEX_ECP_C
 *
 * Enable the elliptic curve over GF(p) library.
 *
 * Module:  library/ecp.c
 * Caller:  library/ecdh.c
 *          library/ecdsa.c
 *          library/ecjpake.c
 *
 * Requires: IOTEX_BIGNUM_C and at least one IOTEX_ECP_DP_XXX_ENABLED
 */
#define IOTEX_ECP_C

/**
 * \def IOTEX_ENTROPY_C
 *
 * Enable the platform-specific entropy code.
 *
 * Module:  library/entropy.c
 * Caller:
 *
 * Requires: IOTEX_SHA512_C or IOTEX_SHA256_C
 *
 * This module provides a generic entropy pool
 */
#define IOTEX_ENTROPY_C

/**
 * \def IOTEX_ERROR_C
 *
 * Enable error code to error string conversion.
 *
 * Module:  library/error.c
 * Caller:
 *
 * This module enables iotex_strerror().
 */
//#define IOTEX_ERROR_C

/**
 * \def IOTEX_GCM_C
 *
 * Enable the Galois/Counter Mode (GCM).
 *
 * Module:  library/gcm.c
 *
 * Requires: IOTEX_CIPHER_C, IOTEX_AES_C or IOTEX_CAMELLIA_C or
 *                             IOTEX_ARIA_C
 *
 * This module enables the AES-GCM and CAMELLIA-GCM ciphersuites, if other
 * requisites are enabled as well.
 */
//#define IOTEX_GCM_C

/**
 * \def IOTEX_HKDF_C
 *
 * Enable the HKDF algorithm (RFC 5869).
 *
 * Module:  library/hkdf.c
 * Caller:
 *
 * Requires: IOTEX_MD_C
 *
 * This module adds support for the Hashed Message Authentication Code
 * (HMAC)-based key derivation function (HKDF).
 */
#define IOTEX_HKDF_C

/**
 * \def IOTEX_HMAC_DRBG_C
 *
 * Enable the HMAC_DRBG random generator.
 *
 * Module:  library/hmac_drbg.c
 * Caller:
 *
 * Requires: IOTEX_MD_C
 *
 * Uncomment to enable the HMAC_DRBG random number generator.
 */
#define IOTEX_HMAC_DRBG_C

/**
 * \def IOTEX_NIST_KW_C
 *
 * Enable the Key Wrapping mode for 128-bit block ciphers,
 * as defined in NIST SP 800-38F. Only KW and KWP modes
 * are supported. At the moment, only AES is approved by NIST.
 *
 * Module:  library/nist_kw.c
 *
 * Requires: IOTEX_AES_C and IOTEX_CIPHER_C
 */
//#define IOTEX_NIST_KW_C

/**
 * \def IOTEX_MD_C
 *
 * Enable the generic message digest layer.
 *
 * Module:  library/md.c
 * Caller:  library/constant_time.c
 *          library/ecdsa.c
 *          library/ecjpake.c
 *          library/hkdf.c
 *          library/hmac_drbg.c
 *          library/pk.c
 *          library/pkcs5.c
 *          library/pkcs12.c
 *          library/psa_crypto_ecp.c
 *          library/psa_crypto_rsa.c
 *          library/rsa.c
 *          library/ssl_cookie.c
 *          library/ssl_msg.c
 *          library/ssl_tls.c
 *          library/x509.c
 *          library/x509_crt.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define IOTEX_MD_C

/**
 * \def IOTEX_MD5_C
 *
 * Enable the MD5 hash algorithm.
 *
 * Module:  library/md5.c
 * Caller:  library/md.c
 *          library/pem.c
 *          library/ssl_tls.c
 *
 * This module is required for TLS 1.2 depending on the handshake parameters.
 * Further, it is used for checking MD5-signed certificates, and for PBKDF1
 * when decrypting PEM-encoded encrypted keys.
 *
 * \warning   MD5 is considered a weak message digest and its use constitutes a
 *            security risk. If possible, we recommend avoiding dependencies on
 *            it, and considering stronger message digests instead.
 *
 */
//#define IOTEX_MD5_C

/**
 * \def IOTEX_MEMORY_BUFFER_ALLOC_C
 *
 * Enable the buffer allocator implementation that makes use of a (stack)
 * based buffer to 'allocate' dynamic memory. (replaces calloc() and free()
 * calls)
 *
 * Module:  library/memory_buffer_alloc.c
 *
 * Requires: IOTEX_PLATFORM_C
 *           IOTEX_PLATFORM_MEMORY (to use it within mbed TLS)
 *
 * Enable this module to enable the buffer memory allocator.
 */
//#define IOTEX_MEMORY_BUFFER_ALLOC_C

/**
 * \def IOTEX_NET_C
 *
 * Enable the TCP and UDP over IPv6/IPv4 networking routines.
 *
 * \note This module only works on POSIX/Unix (including Linux, BSD and OS X)
 * and Windows. For other platforms, you'll want to disable it, and write your
 * own networking callbacks to be passed to \c iotex_ssl_set_bio().
 *
 * \note See also our Knowledge Base article about porting to a new
 * environment:
 * https://tls.mbed.org/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS
 *
 * Module:  library/net_sockets.c
 *
 * This module provides networking routines.
 */
//#define IOTEX_NET_C

/**
 * \def IOTEX_OID_C
 *
 * Enable the OID database.
 *
 * Module:  library/oid.c
 * Caller:  library/asn1write.c
 *          library/pkcs5.c
 *          library/pkparse.c
 *          library/pkwrite.c
 *          library/rsa.c
 *          library/x509.c
 *          library/x509_create.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * This modules translates between OIDs and internal values.
 */
#define IOTEX_OID_C

/**
 * \def IOTEX_PADLOCK_C
 *
 * Enable VIA Padlock support on x86.
 *
 * Module:  library/padlock.c
 * Caller:  library/aes.c
 *
 * Requires: IOTEX_HAVE_ASM
 *
 * This modules adds support for the VIA PadLock on x86.
 */
//#define IOTEX_PADLOCK_C

/**
 * \def IOTEX_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: IOTEX_BASE64_C
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define IOTEX_PEM_PARSE_C

/**
 * \def IOTEX_PEM_WRITE_C
 *
 * Enable PEM encoding / writing.
 *
 * Module:  library/pem.c
 * Caller:  library/pkwrite.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * Requires: IOTEX_BASE64_C
 *
 * This modules adds support for encoding / writing PEM files.
 */
#define IOTEX_PEM_WRITE_C

/**
 * \def IOTEX_PK_C
 *
 * Enable the generic public (asymmetric) key layer.
 *
 * Module:  library/pk.c
 * Caller:  library/psa_crypto_rsa.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *          library/x509.c
 *
 * Requires: IOTEX_MD_C, IOTEX_RSA_C or IOTEX_ECP_C
 *
 * Uncomment to enable generic public key wrappers.
 */
//#define IOTEX_PK_C

/**
 * \def IOTEX_PK_PARSE_C
 *
 * Enable the generic public (asymmetric) key parser.
 *
 * Module:  library/pkparse.c
 * Caller:  library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: IOTEX_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
//#define IOTEX_PK_PARSE_C

/**
 * \def IOTEX_PK_WRITE_C
 *
 * Enable the generic public (asymmetric) key writer.
 *
 * Module:  library/pkwrite.c
 * Caller:  library/x509write.c
 *
 * Requires: IOTEX_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
//#define IOTEX_PK_WRITE_C

/**
 * \def IOTEX_PKCS5_C
 *
 * Enable PKCS#5 functions.
 *
 * Module:  library/pkcs5.c
 *
 * Requires: IOTEX_CIPHER_C, IOTEX_MD_C
 *
 * This module adds support for the PKCS#5 functions.
 */
#define IOTEX_PKCS5_C

/**
 * \def IOTEX_PKCS12_C
 *
 * Enable PKCS#12 PBE functions.
 * Adds algorithms for parsing PKCS#8 encrypted private keys
 *
 * Module:  library/pkcs12.c
 * Caller:  library/pkparse.c
 *
 * Requires: IOTEX_ASN1_PARSE_C, IOTEX_CIPHER_C, IOTEX_MD_C
 *
 * This module enables PKCS#12 functions.
 */
//#define IOTEX_PKCS12_C

/**
 * \def IOTEX_PLATFORM_C
 *
 * Enable the platform abstraction layer that allows you to re-assign
 * functions like calloc(), free(), snprintf(), printf(), fprintf(), exit().
 *
 * Enabling IOTEX_PLATFORM_C enables to use of IOTEX_PLATFORM_XXX_ALT
 * or IOTEX_PLATFORM_XXX_MACRO directives, allowing the functions mentioned
 * above to be specified at runtime or compile time respectively.
 *
 * \note This abstraction layer must be enabled on Windows (including MSYS2)
 * as other module rely on it for a fixed snprintf implementation.
 *
 * Module:  library/platform.c
 * Caller:  Most other .c files
 *
 * This module enables abstraction of common (libc) functions.
 */
//#define IOTEX_PLATFORM_C

/**
 * \def IOTEX_POLY1305_C
 *
 * Enable the Poly1305 MAC algorithm.
 *
 * Module:  library/poly1305.c
 * Caller:  library/chachapoly.c
 */
#define IOTEX_POLY1305_C

/**
 * \def IOTEX_PSA_CRYPTO_C
 *
 * Enable the Platform Security Architecture cryptography API.
 *
 * Module:  library/psa_crypto.c
 *
 * Requires: IOTEX_CIPHER_C,
 *           either IOTEX_CTR_DRBG_C and IOTEX_ENTROPY_C,
 *           or IOTEX_HMAC_DRBG_C and IOTEX_ENTROPY_C,
 *           or IOTEX_PSA_CRYPTO_EXTERNAL_RNG.
 *
 */
#define IOTEX_PSA_CRYPTO_C

/**
 * \def IOTEX_PSA_CRYPTO_SE_C
 *
 * Enable dynamic secure element support in the Platform Security Architecture
 * cryptography API.
 *
 * \deprecated This feature is deprecated. Please switch to the driver
 *             interface enabled by #IOTEX_PSA_CRYPTO_DRIVERS.
 *
 * Module:  library/psa_crypto_se.c
 *
 * Requires: IOTEX_PSA_CRYPTO_C, IOTEX_PSA_CRYPTO_STORAGE_C
 *
 */
//#define IOTEX_PSA_CRYPTO_SE_C

/**
 * \def IOTEX_PSA_CRYPTO_STORAGE_C
 *
 * Enable the Platform Security Architecture persistent key storage.
 *
 * Module:  library/psa_crypto_storage.c
 *
 * Requires: IOTEX_PSA_CRYPTO_C,
 *           either IOTEX_PSA_ITS_FILE_C or a native implementation of
 *           the PSA ITS interface
 */
#define IOTEX_PSA_CRYPTO_STORAGE_C

/**
 * \def IOTEX_PSA_ITS_FILE_C
 *
 * Enable the emulation of the Platform Security Architecture
 * Internal Trusted Storage (PSA ITS) over files.
 *
 * Module:  library/psa_its_file.c
 *
 * Requires: IOTEX_FS_IO
 */
//#define IOTEX_PSA_ITS_FILE_C

/**
 * \def IOTEX_PSA_ITS_FLASH_C
 *
 * Enable the emulation of the Platform Security Architecture
 * Internal Trusted Storage (PSA ITS) over flash.
 *
 * Module:  library/psa_its_flash.c
 *
 * Requires: 
 */
//#define IOTEX_PSA_ITS_FLASH_C

/**
 * \def IOTEX_PSA_ITS_NVS_C
 *
 * Enable the emulation of the Platform Security Architecture
 * Internal Trusted Storage (PSA ITS) over NVS.
 *
 * Module:  library/psa_its_nvs.c
 *
 * Requires: 
 */
#define IOTEX_PSA_ITS_NVS_C

/**
 * \def IOTEX_RIPEMD160_C
 *
 * Enable the RIPEMD-160 hash algorithm.
 *
 * Module:  library/ripemd160.c
 * Caller:  library/md.c
 *
 */
//#define IOTEX_RIPEMD160_C

/**
 * \def IOTEX_RSA_C
 *
 * Enable the RSA public-key cryptosystem.
 *
 * Module:  library/rsa.c
 *          library/rsa_alt_helpers.c
 * Caller:  library/pk.c
 *          library/psa_crypto.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      RSA, DHE-RSA, ECDHE-RSA, RSA-PSK
 *
 * Requires: IOTEX_BIGNUM_C, IOTEX_OID_C
 */
//#define IOTEX_RSA_C

/**
 * \def IOTEX_SHA1_C
 *
 * Enable the SHA1 cryptographic hash algorithm.
 *
 * Module:  library/sha1.c
 * Caller:  library/md.c
 *          library/psa_crypto_hash.c
 *
 * This module is required for TLS 1.2 depending on the handshake parameters,
 * and for SHA1-signed certificates.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. If possible, we recommend avoiding dependencies
 *            on it, and considering stronger message digests instead.
 *
 */
//#define IOTEX_SHA1_C

/**
 * \def IOTEX_SHA224_C
 *
 * Enable the SHA-224 cryptographic hash algorithm.
 *
 * Requires: IOTEX_SHA256_C. The library does not currently support enabling
 *           SHA-224 without SHA-256.
 *
 * Module:  library/sha256.c
 * Caller:  library/md.c
 *          library/ssl_cookie.c
 *
 * This module adds support for SHA-224.
 */
#define IOTEX_SHA224_C

/**
 * \def IOTEX_SHA256_C
 *
 * Enable the SHA-256 cryptographic hash algorithm.
 *
 * Requires: IOTEX_SHA224_C. The library does not currently support enabling
 *           SHA-256 without SHA-224.
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module adds support for SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define IOTEX_SHA256_C

/**
 * \def IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT
 *
 * Enable acceleration of the SHA-256 and SHA-224 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions if they are available at runtime.
 * If not, the library will fall back to the C implementation.
 *
 * \note If IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT is defined when building
 * for a non-Aarch64 build it will be silently ignored.
 *
 * \note The code uses Neon intrinsics, so \c CFLAGS must be set to a minimum
 * of \c -march=armv8-a+crypto.
 *
 * \warning IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT cannot be defined at the
 * same time as IOTEX_SHA256_USE_A64_CRYPTO_ONLY.
 *
 * Requires: IOTEX_SHA256_C.
 *
 * Module:  library/sha256.c
 *
 * Uncomment to have the library check for the A64 SHA-256 crypto extensions
 * and use them if available.
 */
//#define IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT

/**
 * \def IOTEX_SHA256_USE_A64_CRYPTO_ONLY
 *
 * Enable acceleration of the SHA-256 and SHA-224 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions, which must be available at runtime
 * or else an illegal instruction fault will occur.
 *
 * \note This allows builds with a smaller code size than with
 * IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT
 *
 * \note The code uses Neon intrinsics, so \c CFLAGS must be set to a minimum
 * of \c -march=armv8-a+crypto.
 *
 * \warning IOTEX_SHA256_USE_A64_CRYPTO_ONLY cannot be defined at the same
 * time as IOTEX_SHA256_USE_A64_CRYPTO_IF_PRESENT.
 *
 * Requires: IOTEX_SHA256_C.
 *
 * Module:  library/sha256.c
 *
 * Uncomment to have the library use the A64 SHA-256 crypto extensions
 * unconditionally.
 */
//#define IOTEX_SHA256_USE_A64_CRYPTO_ONLY

/**
 * \def IOTEX_SHA384_C
 *
 * Enable the SHA-384 cryptographic hash algorithm.
 *
 * Requires: IOTEX_SHA512_C
 *
 * Module:  library/sha512.c
 * Caller:  library/md.c
 *          library/psa_crypto_hash.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * Comment to disable SHA-384
 */
//#define IOTEX_SHA384_C

/**
 * \def IOTEX_SHA512_C
 *
 * Enable SHA-512 cryptographic hash algorithms.
 *
 * Module:  library/sha512.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_tls.c
 *          library/ssl_cookie.c
 *
 * This module adds support for SHA-512.
 */
//#define IOTEX_SHA512_C

/**
 * \def IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT
 *
 * Enable acceleration of the SHA-512 and SHA-384 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions if they are available at runtime.
 * If not, the library will fall back to the C implementation.
 *
 * \note If IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT is defined when building
 * for a non-Aarch64 build it will be silently ignored.
 *
 * \note The code uses the SHA-512 Neon intrinsics, so requires GCC >= 8 or
 * Clang >= 7, and \c CFLAGS must be set to a minimum of
 * \c -march=armv8.2-a+sha3. An optimisation level of \c -O3 generates the
 * fastest code.
 *
 * \warning IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT cannot be defined at the
 * same time as IOTEX_SHA512_USE_A64_CRYPTO_ONLY.
 *
 * Requires: IOTEX_SHA512_C.
 *
 * Module:  library/sha512.c
 *
 * Uncomment to have the library check for the A64 SHA-512 crypto extensions
 * and use them if available.
 */
//#define IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT

/**
 * \def IOTEX_SHA512_USE_A64_CRYPTO_ONLY
 *
 * Enable acceleration of the SHA-512 and SHA-384 cryptographic hash algorithms
 * with the ARMv8 cryptographic extensions, which must be available at runtime
 * or else an illegal instruction fault will occur.
 *
 * \note This allows builds with a smaller code size than with
 * IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT
 *
 * \note The code uses the SHA-512 Neon intrinsics, so requires GCC >= 8 or
 * Clang >= 7, and \c CFLAGS must be set to a minimum of
 * \c -march=armv8.2-a+sha3. An optimisation level of \c -O3 generates the
 * fastest code.
 *
 * \warning IOTEX_SHA512_USE_A64_CRYPTO_ONLY cannot be defined at the same
 * time as IOTEX_SHA512_USE_A64_CRYPTO_IF_PRESENT.
 *
 * Requires: IOTEX_SHA512_C.
 *
 * Module:  library/sha512.c
 *
 * Uncomment to have the library use the A64 SHA-512 crypto extensions
 * unconditionally.
 */
//#define IOTEX_SHA512_USE_A64_CRYPTO_ONLY

/**
 * \def IOTEX_SSL_CACHE_C
 *
 * Enable simple SSL cache implementation.
 *
 * Module:  library/ssl_cache.c
 * Caller:
 *
 * Requires: IOTEX_SSL_CACHE_C
 */
//#define IOTEX_SSL_CACHE_C

/**
 * \def IOTEX_SSL_COOKIE_C
 *
 * Enable basic implementation of DTLS cookies for hello verification.
 *
 * Module:  library/ssl_cookie.c
 * Caller:
 */
//#define IOTEX_SSL_COOKIE_C

/**
 * \def IOTEX_SSL_TICKET_C
 *
 * Enable an implementation of TLS server-side callbacks for session tickets.
 *
 * Module:  library/ssl_ticket.c
 * Caller:
 *
 * Requires: IOTEX_CIPHER_C || IOTEX_USE_PSA_CRYPTO
 */
//#define IOTEX_SSL_TICKET_C

/**
 * \def IOTEX_SSL_CLI_C
 *
 * Enable the SSL/TLS client code.
 *
 * Module:  library/ssl*_client.c
 * Caller:
 *
 * Requires: IOTEX_SSL_TLS_C
 *
 * This module is required for SSL/TLS client support.
 */
//#define IOTEX_SSL_CLI_C

/**
 * \def IOTEX_SSL_SRV_C
 *
 * Enable the SSL/TLS server code.
 *
 * Module:  library/ssl*_server.c
 * Caller:
 *
 * Requires: IOTEX_SSL_TLS_C
 *
 * This module is required for SSL/TLS server support.
 */
//#define IOTEX_SSL_SRV_C

/**
 * \def IOTEX_SSL_TLS_C
 *
 * Enable the generic SSL/TLS code.
 *
 * Module:  library/ssl_tls.c
 * Caller:  library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * Requires: IOTEX_CIPHER_C, IOTEX_MD_C
 *           and at least one of the IOTEX_SSL_PROTO_XXX defines
 *
 * This module is required for SSL/TLS.
 */
//#define IOTEX_SSL_TLS_C

/**
 * \def IOTEX_THREADING_C
 *
 * Enable the threading abstraction layer.
 * By default mbed TLS assumes it is used in a non-threaded environment or that
 * contexts are not shared between threads. If you do intend to use contexts
 * between threads, you will need to enable this layer to prevent race
 * conditions. See also our Knowledge Base article about threading:
 * https://tls.mbed.org/kb/development/thread-safety-and-multi-threading
 *
 * Module:  library/threading.c
 *
 * This allows different threading implementations (self-implemented or
 * provided).
 *
 * You will have to enable either IOTEX_THREADING_ALT or
 * IOTEX_THREADING_PTHREAD.
 *
 * Enable this layer to allow use of mutexes within mbed TLS
 */
//#define IOTEX_THREADING_C

/**
 * \def IOTEX_TIMING_C
 *
 * Enable the semi-portable timing interface.
 *
 * \note The provided implementation only works on POSIX/Unix (including Linux,
 * BSD and OS X) and Windows. On other platforms, you can either disable that
 * module and provide your own implementations of the callbacks needed by
 * \c iotex_ssl_set_timer_cb() for DTLS, or leave it enabled and provide
 * your own implementation of the whole module by setting
 * \c IOTEX_TIMING_ALT in the current file.
 *
 * \note The timing module will include time.h on suitable platforms
 *       regardless of the setting of IOTEX_HAVE_TIME, unless
 *       IOTEX_TIMING_ALT is used. See timing.c for more information.
 *
 * \note See also our Knowledge Base article about porting to a new
 * environment:
 * https://tls.mbed.org/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS
 *
 * Module:  library/timing.c
 */
//#define IOTEX_TIMING_C

/**
 * \def IOTEX_VERSION_C
 *
 * Enable run-time version information.
 *
 * Module:  library/version.c
 *
 * This module provides run-time version information.
 */
#define IOTEX_VERSION_C

/**
 * \def IOTEX_X509_USE_C
 *
 * Enable X.509 core for using certificates.
 *
 * Module:  library/x509.c
 * Caller:  library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: IOTEX_ASN1_PARSE_C, IOTEX_BIGNUM_C, IOTEX_OID_C,
 *           IOTEX_PK_PARSE_C
 *
 * This module is required for the X.509 parsing modules.
 */
//#define IOTEX_X509_USE_C

/**
 * \def IOTEX_X509_CRT_PARSE_C
 *
 * Enable X.509 certificate parsing.
 *
 * Module:  library/x509_crt.c
 * Caller:  library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * Requires: IOTEX_X509_USE_C
 *
 * This module is required for X.509 certificate parsing.
 */
//#define IOTEX_X509_CRT_PARSE_C

/**
 * \def IOTEX_X509_CRL_PARSE_C
 *
 * Enable X.509 CRL parsing.
 *
 * Module:  library/x509_crl.c
 * Caller:  library/x509_crt.c
 *
 * Requires: IOTEX_X509_USE_C
 *
 * This module is required for X.509 CRL parsing.
 */
//#define IOTEX_X509_CRL_PARSE_C

/**
 * \def IOTEX_X509_CSR_PARSE_C
 *
 * Enable X.509 Certificate Signing Request (CSR) parsing.
 *
 * Module:  library/x509_csr.c
 * Caller:  library/x509_crt_write.c
 *
 * Requires: IOTEX_X509_USE_C
 *
 * This module is used for reading X.509 certificate request.
 */
//#define IOTEX_X509_CSR_PARSE_C

/**
 * \def IOTEX_X509_CREATE_C
 *
 * Enable X.509 core for creating certificates.
 *
 * Module:  library/x509_create.c
 *
 * Requires: IOTEX_BIGNUM_C, IOTEX_OID_C, IOTEX_PK_WRITE_C
 *
 * This module is the basis for creating X.509 certificates and CSRs.
 */
//#define IOTEX_X509_CREATE_C

/**
 * \def IOTEX_X509_CRT_WRITE_C
 *
 * Enable creating X.509 certificates.
 *
 * Module:  library/x509_crt_write.c
 *
 * Requires: IOTEX_X509_CREATE_C
 *
 * This module is required for X.509 certificate creation.
 */
//#define IOTEX_X509_CRT_WRITE_C

/**
 * \def IOTEX_X509_CSR_WRITE_C
 *
 * Enable creating X.509 Certificate Signing Requests (CSR).
 *
 * Module:  library/x509_csr_write.c
 *
 * Requires: IOTEX_X509_CREATE_C
 *
 * This module is required for X.509 certificate request writing.
 */
//#define IOTEX_X509_CSR_WRITE_C

/** \} name SECTION: mbed TLS modules */

/**
 * \name SECTION: General configuration options
 *
 * This section contains Mbed TLS build settings that are not associated
 * with a particular module.
 *
 * \{
 */

/**
 * \def IOTEX_CONFIG_FILE
 *
 * If defined, this is a header which will be included instead of
 * `"mbedtls/iotex_config.h"`.
 * This header file specifies the compile-time configuration of Mbed TLS.
 * Unlike other configuration options, this one must be defined on the
 * compiler command line: a definition in `iotex_config.h` would have
 * no effect.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define IOTEX_CONFIG_FILE "mbedtls/iotex_config.h"

/**
 * \def IOTEX_USER_CONFIG_FILE
 *
 * If defined, this is a header which will be included after
 * `"mbedtls/iotex_config.h"` or #IOTEX_CONFIG_FILE.
 * This allows you to modify the default configuration, including the ability
 * to undefine options that are enabled by default.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define IOTEX_USER_CONFIG_FILE "/dev/null"

/**
 * \def IOTEX_PSA_CRYPTO_CONFIG_FILE
 *
 * If defined, this is a header which will be included instead of
 * `"psa/crypto_config.h"`.
 * This header file specifies which cryptographic mechanisms are available
 * through the PSA API when #IOTEX_PSA_CRYPTO_CONFIG is enabled, and
 * is not used when #IOTEX_PSA_CRYPTO_CONFIG is disabled.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define IOTEX_PSA_CRYPTO_CONFIG_FILE "psa/crypto_config.h"

/**
 * \def IOTEX_PSA_CRYPTO_USER_CONFIG_FILE
 *
 * If defined, this is a header which will be included after
 * `"psa/crypto_config.h"` or #IOTEX_PSA_CRYPTO_CONFIG_FILE.
 * This allows you to modify the default configuration, including the ability
 * to undefine options that are enabled by default.
 *
 * This macro is expanded after an <tt>\#include</tt> directive. This is a popular but
 * non-standard feature of the C language, so this feature is only available
 * with compilers that perform macro expansion on an <tt>\#include</tt> line.
 *
 * The value of this symbol is typically a path in double quotes, either
 * absolute or relative to a directory on the include search path.
 */
//#define IOTEX_PSA_CRYPTO_USER_CONFIG_FILE "/dev/null"

/** \} name SECTION: General configuration options */

/**
 * \name SECTION: Module configuration options
 *
 * This section allows for the setting of module specific sizes and
 * configuration options. The default values are already present in the
 * relevant header files and should suffice for the regular use cases.
 *
 * Our advice is to enable options and change their values here
 * only if you have a good reason and know the consequences.
 * \{
 */
/* The Doxygen documentation here is used when a user comments out a
 * setting and runs doxygen themselves. On the other hand, when we typeset
 * the full documentation including disabled settings, the documentation
 * in specific modules' header files is used if present. When editing this
 * file, make sure that each option is documented in exactly one place,
 * plus optionally a same-line Doxygen comment here if there is a Doxygen
 * comment in the specific module. */

/* MPI / BIGNUM options */
//#define IOTEX_MPI_WINDOW_SIZE            6 /**< Maximum window size used. */
//#define IOTEX_MPI_MAX_SIZE            1024 /**< Maximum number of bytes for usable MPIs. */

/* CTR_DRBG options */
//#define IOTEX_CTR_DRBG_ENTROPY_LEN               48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
//#define IOTEX_CTR_DRBG_RESEED_INTERVAL        10000 /**< Interval before reseed is performed by default */
//#define IOTEX_CTR_DRBG_MAX_INPUT                256 /**< Maximum number of additional input bytes */
//#define IOTEX_CTR_DRBG_MAX_REQUEST             1024 /**< Maximum number of requested bytes per call */
//#define IOTEX_CTR_DRBG_MAX_SEED_INPUT           384 /**< Maximum size of (re)seed buffer */

/* HMAC_DRBG options */
//#define IOTEX_HMAC_DRBG_RESEED_INTERVAL   10000 /**< Interval before reseed is performed by default */
//#define IOTEX_HMAC_DRBG_MAX_INPUT           256 /**< Maximum number of additional input bytes */
//#define IOTEX_HMAC_DRBG_MAX_REQUEST        1024 /**< Maximum number of requested bytes per call */
//#define IOTEX_HMAC_DRBG_MAX_SEED_INPUT      384 /**< Maximum size of (re)seed buffer */

/* ECP options */
//#define IOTEX_ECP_WINDOW_SIZE            4 /**< Maximum window size used */
//#define IOTEX_ECP_FIXED_POINT_OPTIM      1 /**< Enable fixed-point speed-up */

/* Entropy options */
//#define IOTEX_ENTROPY_MAX_SOURCES                20 /**< Maximum number of sources supported */
//#define IOTEX_ENTROPY_MAX_GATHER                128 /**< Maximum amount requested from entropy sources */
//#define IOTEX_ENTROPY_MIN_HARDWARE               32 /**< Default minimum number of bytes required for the hardware entropy source iotex_hardware_poll() before entropy is released */

/* Memory buffer allocator options */
//#define IOTEX_MEMORY_ALIGN_MULTIPLE      4 /**< Align on multiples of this value */

/* Platform options */
//#define IOTEX_PLATFORM_STD_MEM_HDR   <stdlib.h> /**< Header to include if IOTEX_PLATFORM_NO_STD_FUNCTIONS is defined. Don't define if no header is needed. */
//#define IOTEX_PLATFORM_STD_CALLOC        calloc /**< Default allocator to use, can be undefined */
//#define IOTEX_PLATFORM_STD_FREE            free /**< Default free to use, can be undefined */
//#define IOTEX_PLATFORM_STD_SETBUF      setbuf /**< Default setbuf to use, can be undefined */
//#define IOTEX_PLATFORM_STD_EXIT            exit /**< Default exit to use, can be undefined */
//#define IOTEX_PLATFORM_STD_TIME            time /**< Default time to use, can be undefined. IOTEX_HAVE_TIME must be enabled */
//#define IOTEX_PLATFORM_STD_FPRINTF      fprintf /**< Default fprintf to use, can be undefined */
//#define IOTEX_PLATFORM_STD_PRINTF        printf /**< Default printf to use, can be undefined */
/* Note: your snprintf must correctly zero-terminate the buffer! */
//#define IOTEX_PLATFORM_STD_SNPRINTF    snprintf /**< Default snprintf to use, can be undefined */
//#define IOTEX_PLATFORM_STD_EXIT_SUCCESS       0 /**< Default exit value to use, can be undefined */
//#define IOTEX_PLATFORM_STD_EXIT_FAILURE       1 /**< Default exit value to use, can be undefined */
//#define IOTEX_PLATFORM_STD_NV_SEED_READ   iotex_platform_std_nv_seed_read /**< Default nv_seed_read function to use, can be undefined */
//#define IOTEX_PLATFORM_STD_NV_SEED_WRITE  iotex_platform_std_nv_seed_write /**< Default nv_seed_write function to use, can be undefined */
//#define IOTEX_PLATFORM_STD_NV_SEED_FILE  "seedfile" /**< Seed file to read/write with default implementation */

/* To Use Function Macros IOTEX_PLATFORM_C must be enabled */
/* IOTEX_PLATFORM_XXX_MACRO and IOTEX_PLATFORM_XXX_ALT cannot both be defined */
//#define IOTEX_PLATFORM_CALLOC_MACRO        calloc /**< Default allocator macro to use, can be undefined */
//#define IOTEX_PLATFORM_FREE_MACRO            free /**< Default free macro to use, can be undefined */
//#define IOTEX_PLATFORM_EXIT_MACRO            exit /**< Default exit macro to use, can be undefined */
//#define IOTEX_PLATFORM_SETBUF_MACRO      setbuf /**< Default setbuf macro to use, can be undefined */
//#define IOTEX_PLATFORM_TIME_MACRO            time /**< Default time macro to use, can be undefined. IOTEX_HAVE_TIME must be enabled */
//#define IOTEX_PLATFORM_TIME_TYPE_MACRO       time_t /**< Default time macro to use, can be undefined. IOTEX_HAVE_TIME must be enabled */
//#define IOTEX_PLATFORM_FPRINTF_MACRO      fprintf /**< Default fprintf macro to use, can be undefined */
//#define IOTEX_PLATFORM_PRINTF_MACRO        printf /**< Default printf macro to use, can be undefined */
/* Note: your snprintf must correctly zero-terminate the buffer! */
//#define IOTEX_PLATFORM_SNPRINTF_MACRO    snprintf /**< Default snprintf macro to use, can be undefined */
//#define IOTEX_PLATFORM_VSNPRINTF_MACRO    vsnprintf /**< Default vsnprintf macro to use, can be undefined */
//#define IOTEX_PLATFORM_NV_SEED_READ_MACRO   iotex_platform_std_nv_seed_read /**< Default nv_seed_read function to use, can be undefined */
//#define IOTEX_PLATFORM_NV_SEED_WRITE_MACRO  iotex_platform_std_nv_seed_write /**< Default nv_seed_write function to use, can be undefined */

/** \def IOTEX_CHECK_RETURN
 *
 * This macro is used at the beginning of the declaration of a function
 * to indicate that its return value should be checked. It should
 * instruct the compiler to emit a warning or an error if the function
 * is called without checking its return value.
 *
 * There is a default implementation for popular compilers in platform_util.h.
 * You can override the default implementation by defining your own here.
 *
 * If the implementation here is empty, this will effectively disable the
 * checking of functions' return values.
 */
//#define IOTEX_CHECK_RETURN __attribute__((__warn_unused_result__))

/** \def IOTEX_IGNORE_RETURN
 *
 * This macro requires one argument, which should be a C function call.
 * If that function call would cause a #IOTEX_CHECK_RETURN warning, this
 * warning is suppressed.
 */
//#define IOTEX_IGNORE_RETURN( result ) ((void) !(result))

/* PSA options */
/**
 * Use HMAC_DRBG with the specified hash algorithm for HMAC_DRBG for the
 * PSA crypto subsystem.
 *
 * If this option is unset:
 * - If CTR_DRBG is available, the PSA subsystem uses it rather than HMAC_DRBG.
 * - Otherwise, the PSA subsystem uses HMAC_DRBG with either
 *   #IOTEX_MD_SHA512 or #IOTEX_MD_SHA256 based on availability and
 *   on unspecified heuristics.
 */
//#define IOTEX_PSA_HMAC_DRBG_MD_TYPE IOTEX_MD_SHA256

/** \def IOTEX_PSA_KEY_SLOT_COUNT
 * Restrict the PSA library to supporting a maximum amount of simultaneously
 * loaded keys. A loaded key is a key stored by the PSA Crypto core as a
 * volatile key, or a persistent key which is loaded temporarily by the
 * library as part of a crypto operation in flight.
 *
 * If this option is unset, the library will fall back to a default value of
 * 32 keys.
 */
//#define IOTEX_PSA_KEY_SLOT_COUNT 32

/* SSL Cache options */
//#define IOTEX_SSL_CACHE_DEFAULT_TIMEOUT       86400 /**< 1 day  */
//#define IOTEX_SSL_CACHE_DEFAULT_MAX_ENTRIES      50 /**< Maximum entries in cache */

/* SSL options */

/** \def IOTEX_SSL_IN_CONTENT_LEN
 *
 * Maximum length (in bytes) of incoming plaintext fragments.
 *
 * This determines the size of the incoming TLS I/O buffer in such a way
 * that it is capable of holding the specified amount of plaintext data,
 * regardless of the protection mechanism used.
 *
 * \note When using a value less than the default of 16KB on the client, it is
 *       recommended to use the Maximum Fragment Length (MFL) extension to
 *       inform the server about this limitation. On the server, there
 *       is no supported, standardized way of informing the client about
 *       restriction on the maximum size of incoming messages, and unless
 *       the limitation has been communicated by other means, it is recommended
 *       to only change the outgoing buffer size #IOTEX_SSL_OUT_CONTENT_LEN
 *       while keeping the default value of 16KB for the incoming buffer.
 *
 * Uncomment to set the maximum plaintext size of the incoming I/O buffer.
 */
//#define IOTEX_SSL_IN_CONTENT_LEN              16384

/** \def IOTEX_SSL_CID_IN_LEN_MAX
 *
 * The maximum length of CIDs used for incoming DTLS messages.
 *
 */
//#define IOTEX_SSL_CID_IN_LEN_MAX 32

/** \def IOTEX_SSL_CID_OUT_LEN_MAX
 *
 * The maximum length of CIDs used for outgoing DTLS messages.
 *
 */
//#define IOTEX_SSL_CID_OUT_LEN_MAX 32

/** \def IOTEX_SSL_CID_TLS1_3_PADDING_GRANULARITY
 *
 * This option controls the use of record plaintext padding
 * in TLS 1.3 and when using the Connection ID extension in DTLS 1.2.
 *
 * The padding will always be chosen so that the length of the
 * padded plaintext is a multiple of the value of this option.
 *
 * Note: A value of \c 1 means that no padding will be used
 *       for outgoing records.
 *
 * Note: On systems lacking division instructions,
 *       a power of two should be preferred.
 */
//#define IOTEX_SSL_CID_TLS1_3_PADDING_GRANULARITY 16

/** \def IOTEX_SSL_OUT_CONTENT_LEN
 *
 * Maximum length (in bytes) of outgoing plaintext fragments.
 *
 * This determines the size of the outgoing TLS I/O buffer in such a way
 * that it is capable of holding the specified amount of plaintext data,
 * regardless of the protection mechanism used.
 *
 * It is possible to save RAM by setting a smaller outward buffer, while keeping
 * the default inward 16384 byte buffer to conform to the TLS specification.
 *
 * The minimum required outward buffer size is determined by the handshake
 * protocol's usage. Handshaking will fail if the outward buffer is too small.
 * The specific size requirement depends on the configured ciphers and any
 * certificate data which is sent during the handshake.
 *
 * Uncomment to set the maximum plaintext size of the outgoing I/O buffer.
 */
//#define IOTEX_SSL_OUT_CONTENT_LEN             16384

/** \def IOTEX_SSL_DTLS_MAX_BUFFERING
 *
 * Maximum number of heap-allocated bytes for the purpose of
 * DTLS handshake message reassembly and future message buffering.
 *
 * This should be at least 9/8 * IOTEX_SSL_IN_CONTENT_LEN
 * to account for a reassembled handshake message of maximum size,
 * together with its reassembly bitmap.
 *
 * A value of 2 * IOTEX_SSL_IN_CONTENT_LEN (32768 by default)
 * should be sufficient for all practical situations as it allows
 * to reassembly a large handshake message (such as a certificate)
 * while buffering multiple smaller handshake messages.
 *
 */
//#define IOTEX_SSL_DTLS_MAX_BUFFERING             32768

//#define IOTEX_PSK_MAX_LEN               32 /**< Max size of TLS pre-shared keys, in bytes (default 256 bits) */
//#define IOTEX_SSL_COOKIE_TIMEOUT        60 /**< Default expiration delay of DTLS cookies, in seconds if HAVE_TIME, or in number of cookies issued */

/** \def IOTEX_TLS_EXT_CID
 *
 * At the time of writing, the CID extension has not been assigned its
 * final value. Set this configuration option to make Mbed TLS use a
 * different value.
 *
 * A future minor revision of Mbed TLS may change the default value of
 * this option to match evolving standards and usage.
 */
//#define IOTEX_TLS_EXT_CID                        254

/**
 * Complete list of ciphersuites to use, in order of preference.
 *
 * \warning No dependency checking is done on that field! This option can only
 * be used to restrict the set of available ciphersuites. It is your
 * responsibility to make sure the needed modules are active.
 *
 * Use this to save a few hundred bytes of ROM (default ordering of all
 * available ciphersuites) and a few to a few hundred bytes of RAM.
 *
 * The value below is only an example, not the default.
 */
//#define IOTEX_SSL_CIPHERSUITES IOTEX_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,IOTEX_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

/* X509 options */
//#define IOTEX_X509_MAX_INTERMEDIATE_CA   8   /**< Maximum number of intermediate CAs in a verification chain. */
//#define IOTEX_X509_MAX_FILE_PATH_LEN     512 /**< Maximum length of a path/filename string in bytes including the null terminator character ('\0'). */

/**
 * Uncomment the macro to let mbed TLS use your alternate implementation of
 * iotex_platform_zeroize(). This replaces the default implementation in
 * platform_util.c.
 *
 * iotex_platform_zeroize() is a widely used function across the library to
 * zero a block of memory. The implementation is expected to be secure in the
 * sense that it has been written to prevent the compiler from removing calls
 * to iotex_platform_zeroize() as part of redundant code elimination
 * optimizations. However, it is difficult to guarantee that calls to
 * iotex_platform_zeroize() will not be optimized by the compiler as older
 * versions of the C language standards do not provide a secure implementation
 * of memset(). Therefore, IOTEX_PLATFORM_ZEROIZE_ALT enables users to
 * configure their own implementation of iotex_platform_zeroize(), for
 * example by using directives specific to their compiler, features from newer
 * C standards (e.g using memset_s() in C11) or calling a secure memset() from
 * their system (e.g explicit_bzero() in BSD).
 */
//#define IOTEX_PLATFORM_ZEROIZE_ALT

/**
 * Uncomment the macro to let Mbed TLS use your alternate implementation of
 * iotex_platform_gmtime_r(). This replaces the default implementation in
 * platform_util.c.
 *
 * gmtime() is not a thread-safe function as defined in the C standard. The
 * library will try to use safer implementations of this function, such as
 * gmtime_r() when available. However, if Mbed TLS cannot identify the target
 * system, the implementation of iotex_platform_gmtime_r() will default to
 * using the standard gmtime(). In this case, calls from the library to
 * gmtime() will be guarded by the global mutex iotex_threading_gmtime_mutex
 * if IOTEX_THREADING_C is enabled. We recommend that calls from outside the
 * library are also guarded with this mutex to avoid race conditions. However,
 * if the macro IOTEX_PLATFORM_GMTIME_R_ALT is defined, Mbed TLS will
 * unconditionally use the implementation for iotex_platform_gmtime_r()
 * supplied at compile time.
 */
//#define IOTEX_PLATFORM_GMTIME_R_ALT

/**
 * Enable the verified implementations of ECDH primitives from Project Everest
 * (currently only Curve25519). This feature changes the layout of ECDH
 * contexts and therefore is a compatibility break for applications that access
 * fields of a iotex_ecdh_context structure directly. See also
 * IOTEX_ECDH_LEGACY_CONTEXT in include/mbedtls/ecdh.h.
 */
//#define IOTEX_ECDH_VARIANT_EVEREST_ENABLED

#define CRYPTO_USE_NOTHING      0
#define CRYPTO_USE_MBEDTLS      1
#define CRYPTO_USE_TINYCRYPO    2
#define CRYPTO_USE_IOTEXCRYPO   3

//#define IOTEX_PSA_CRYPTO_MODULE_USE   CRYPTO_USE_MBEDTLS
#define IOTEX_PSA_CRYPTO_MODULE_USE   CRYPTO_USE_TINYCRYPO

#ifdef PSA_CRYPTO_BACKENDS_MBEDTLS
#define IOTEX_PORTING_HEAD_FILE     "layer_conf/iotex_cryto_use_mbedtls.h"
#define IOTEX_INCLUDE_PRE           mbedtls

#define iotex_sha256_info   mbedtls_sha256_info    
#define iotex_sha224_info   mbedtls_sha224_info
#endif

//#define IOTEX_PSA_CRYPTO_ACCELERATION_ENABLE

#if defined(IOTEX_PSA_CRYPTO_ACCELERATION_ENABLE)
#define IOTEX_CRYPTO_SHA_ACCELETATION_SUPPORT
#define IOTEX_CRYPTO_AES_ACCELETATION_SUPPORT
#define IOTEX_CRYPTO_RSA_ACCELETATION_SUPPORT
#define IOTEX_CRYPTO_HMAC_ACCELETATION_SUPPORT

#define IOTEX_CRYPTO_CIPHER_ACCELETATION_SUPPORT
#endif


//#define IOTEX_CRYPTO_USE_ACCELERATION_LIB
#define IOTEX_CRYPTO_USE_ACCELERATION_MBEDTLS

//#define IOTEX_KEY_MANAGMENT

/** \} name SECTION: Module configuration options */
