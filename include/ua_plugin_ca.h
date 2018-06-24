//
// Created by markus on 23.06.18.
//

#ifndef OPEN62541_UA_PLUGIN_CA_H
#define OPEN62541_UA_PLUGIN_CA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_types.h"
#include "ua_plugin_log.h"

struct UA_GDSCertificateGroup;
typedef struct UA_GDSCertificateGroup UA_GDSCertificateGroup;

struct UA_GDSCertificateGroup {
    void *context;
    UA_Logger logger;
    UA_StatusCode (*certificateSigningRequest)(void *context,
                                       const UA_ByteString *csr,
                                       UA_ByteString *const certificate);
    UA_StatusCode (*createNewKeyPair) (void *context, UA_String subjectName,
                                       UA_String *privateKeyFormat,
                                       UA_String *privateKeyPassword,
                                       const UA_String *domainNames,
                                       size_t domainNamesSize);

    UA_Boolean  (*isCertificatefromCA) (void *context, UA_ByteString certificate);

    void (*deleteMembers)(UA_GDSCertificateGroup *cv);
};


#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_PLUGIN_CA_H
