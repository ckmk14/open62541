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
struct GDS_CAPlugin;
typedef struct GDS_CAPlugin GDS_CAPlugin;

struct GDS_CAPlugin {
    void *context;
    UA_Logger logger;

    UA_StatusCode (*createNewKeyPair) (GDS_CAPlugin *scg,
                                       UA_String *subjectName,
                                       UA_String *privateKeyFormat,
                                       UA_String *privateKeyPassword,
                                       unsigned  int keySize,
                                       size_t domainNamesSize,
                                       UA_String *domainNamesArray,
                                       UA_ByteString *const certificate,
                                       UA_ByteString *const privateKey,
                                       size_t *issuerCertificateSize,
                                       UA_ByteString **issuerCertificates);

    UA_StatusCode (*certificateSigningRequest) (GDS_CAPlugin *scg,
                                                unsigned int supposedKeySize,
                                                UA_ByteString *certificateSigningRequest,
                                                UA_ByteString *certificate,
                                                size_t *issuerCertificateSize,
                                                UA_ByteString **issuerCertificates);

    UA_Boolean  (*isCertificatefromCA) (void *context, UA_ByteString certificate);

    void (*deleteMembers)(GDS_CAPlugin *cv);
};

typedef struct {
    UA_NodeId certificateGroupId;
    GDS_CAPlugin *ca;
} GDS_CertificateGroup;

#endif

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_PLUGIN_CA_H
