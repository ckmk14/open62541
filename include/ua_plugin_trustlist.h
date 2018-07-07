/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_PLUGIN_TRUSTLIST_H
#define OPEN62541_UA_PLUGIN_TRUSTLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_server.h"

struct UA_TrustList;
typedef struct UA_TrustList UA_TrustList;


struct UA_TrustList {

    // PEM encoded trust list
    UA_ByteString (*getTrustedCertificates) (UA_TrustList *tl);

    // PEM encoded certificate revocation list
    UA_ByteString (*getTrustedCrls) (UA_TrustList *tl);

    UA_StatusCode (*addCertificate)(UA_TrustList *tl, UA_ByteString *certificate);

    UA_StatusCode (*deleteCertificate)(UA_TrustList *tl, UA_ByteString *thumbprint);

    void (*deleteMembers)(UA_TrustList *tl);
};

#endif //OPEN62541_UA_PLUGIN_TRUSTLIST_H
