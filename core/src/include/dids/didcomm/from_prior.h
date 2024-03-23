#ifndef __DID_COMM_FROM_PRIOR__
#define __DID_COMM_FROM_PRIOR__

#include <time.h>

typedef struct _FromPrior {
    char *iss;          // Issuer
    char *sub;          // Subject
    char *aud;          // Audience, skip_serializing_if = "Option::is_none"
    time_t exp;         // Expiration Time, skip_serializing_if = "Option::is_none"
    time_t nbf;         // Not Before, skip_serializing_if = "Option::is_none"
    time_t iat;         // Issurd At, skip_serializing_if = "Option::is_none"
    char *jti;          // JWT ID, skip_serializing_if = "Option::is_none"
} FromPrior;

FromPrior *fromprior_new(char *iss, char *sub);
FromPrior *fromprior_set_aud(FromPrior *fromprior, char *aud);
FromPrior *fromprior_set_exp(FromPrior *fromprior, time_t exp);
FromPrior *fromprior_set_nbf(FromPrior *fromprior, time_t nbf);
FromPrior *fromprior_set_iat(FromPrior *fromprior, time_t iat);
FromPrior *fromprior_set_jti(FromPrior *fromprior, char *jti);

#endif