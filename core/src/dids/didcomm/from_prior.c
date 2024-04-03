#include <stdlib.h>
#include <string.h>
#include "include/dids/didcomm/from_prior.h"

FromPrior *fromprior_new(char *iss, char *sub)
{
    FromPrior *fromprior = NULL;

    if (NULL == iss || NULL == sub)
        return NULL;
    
    fromprior = malloc(sizeof(FromPrior));
    if (NULL == fromprior)
        return NULL;

    memset(fromprior, 0, sizeof(FromPrior));

    fromprior->iss = iss;
    fromprior->sub = sub;

    return fromprior;
}

FromPrior *fromprior_set_aud(FromPrior *fromprior, char *aud)
{
    if (NULL == fromprior || NULL == aud)
        return NULL;

    if (fromprior->aud)
        free(fromprior->aud);

    fromprior->aud = aud;

    return fromprior;
}

FromPrior *fromprior_set_exp(FromPrior *fromprior, time_t exp)
{
    if (NULL == fromprior)
        return NULL;

    fromprior->exp = exp;

    return fromprior;
}

FromPrior *fromprior_set_nbf(FromPrior *fromprior, time_t nbf)
{
    if (NULL == fromprior)
        return NULL;

    fromprior->nbf = nbf;

    return fromprior;
}

FromPrior *fromprior_set_iat(FromPrior *fromprior, time_t iat)
{
    if (NULL == fromprior)
        return NULL;

    fromprior->iat = iat;

    return fromprior;
}

FromPrior *fromprior_set_jti(FromPrior *fromprior, char *jti)
{
    if (NULL == fromprior || NULL == jti)
        return NULL;

    if (fromprior->jti)
        free(fromprior->jti);

    fromprior->jti = jti;

    return fromprior;
}
