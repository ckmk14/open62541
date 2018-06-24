//
// Created by markus on 23.06.18.
//

#include "ua_mbedtls_ca.h"
#include <stdio.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/error.h>

#define UA_LOG_MBEDERR                                                  \
    char errBuff[300];                                                  \
    mbedtls_strerror(mbedErr, errBuff, 300);                            \
    UA_LOG_WARNING(scg->logger, UA_LOGCATEGORY_SERVER, \
                   "mbedTLS returned an error: %s", errBuff);           \

#define UA_MBEDTLS_ERRORHANDLING(errorcode)                             \
    if(mbedErr) {                                                       \
        UA_LOG_MBEDERR                                                  \
        retval = errorcode;                                             \
    }

static UA_StatusCode Create_CAPrivateKey(UA_GDSCertificateGroup *scg,
                                         size_t keySize) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    mbedtls_pk_context pubKey;
    mbedtls_entropy_context entropyContext;
    mbedtls_entropy_init(&entropyContext);

    int mbedErr = mbedtls_entropy_add_source(&entropyContext,
                                         mbedtls_platform_entropy_poll, NULL, 0,
                                         MBEDTLS_ENTROPY_SOURCE_STRONG);
    UA_MBEDTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    if(retval != UA_STATUSCODE_GOOD)
        goto error;

    return UA_STATUSCODE_GOOD;

error:
    UA_LOG_ERROR(scg->logger, UA_LOGCATEGORY_SERVER,
                 "Could not create securityContext");
   // if(securityPolicy->policyContext != NULL)
    //    deleteMembers_sp_basic128rsa15(securityPolicy);
    return retval;
}


static UA_StatusCode certificateSigningRequest (void *context,
                                                const UA_ByteString *csr,
                                                UA_ByteString *const certificate) {

    return UA_STATUSCODE_GOOD;
}

void  UA_InitCA(UA_GDSCertificateGroup *scg, UA_Logger logger) {
    scg->logger = logger;
    scg->certificateSigningRequest = certificateSigningRequest;

    printf("Hallo");
}