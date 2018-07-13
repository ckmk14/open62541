/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef UA_SECURITYPOLICY_BASIC128RSA15_H_
#define UA_SECURITYPOLICY_BASIC128RSA15_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_plugin_securitypolicy.h"
#include "ua_plugin_log.h"

#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>
#include <mbedtls/sha1.h>

typedef struct {
    const UA_SecurityPolicy *securityPolicy;
    UA_ByteString localCertThumbprint;

    mbedtls_ctr_drbg_context drbgContext;
    mbedtls_entropy_context entropyContext;
    mbedtls_md_context_t sha1MdContext;
    mbedtls_pk_context localPrivateKey;
} Basic128Rsa15_PolicyContext;

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Basic128Rsa15(UA_SecurityPolicy *policy,
                                UA_CertificateVerification *certificateVerification,
                                const UA_ByteString localCertificate,
                                const UA_ByteString localPrivateKey,
                                UA_Logger logger);

#ifdef __cplusplus
}
#endif

#endif // UA_SECURITYPOLICY_BASIC128RSA15_H_
