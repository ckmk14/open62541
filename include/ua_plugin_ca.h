/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_PLUGIN_CA_H
#define OPEN62541_UA_PLUGIN_CA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_types.h"
#include "ua_plugin_log.h"

#ifdef UA_ENABLE_GDS

/*
 * A GDSCertificateGroup represents an interface to exactly one CA.
 * Currently only one plugin interface is implemented which uses GnuTLS.
 * */
struct UA_GDSCertificateGroup;
typedef struct UA_GDSCertificateGroup UA_GDSCertificateGroup;

struct UA_GDSCertificateGroup {
    void *context;
    UA_Logger logger;
    UA_StatusCode (*certificateSigningRequest)(UA_GDSCertificateGroup *cg,
                                               const UA_ByteString *csr,
                                               unsigned int supposedKeySize,
                                               UA_ByteString *const certificate);
    UA_StatusCode (*createNewKeyPair) (UA_GDSCertificateGroup *scg,
                                       UA_String subjectName,
                                       UA_String *privateKeyFormat,
                                       UA_String *privateKeyPassword,
                                       unsigned  int keySize,
                                       UA_ByteString *domainNamesArray,
                                       size_t domainNamesSize,
                                       UA_String applicationUri,
                                       UA_ByteString *const certificate,
                                       UA_ByteString *const password);

    UA_Boolean  (*isCertificatefromCA) (void *context, UA_ByteString certificate);

    void (*deleteMembers)(UA_GDSCertificateGroup *cv);
};

#endif

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_PLUGIN_CA_H
