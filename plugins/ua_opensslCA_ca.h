//
// Created by markus on 23.06.18.
//

#ifndef OPEN62541_UA_OPENSSLCA_CA_H
#define OPEN62541_UA_OPENSSLCA_CA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_plugin_ca.h"

#ifdef UA_ENABLE_GDS

UA_EXPORT UA_StatusCode UA_CreateGDSCertificateGroup(UA_GDSCertificateGroup *scg,
                                                     int privateKeySizeCA,
                                                     size_t privateKeyExponent,
                                                     UA_Logger logger);

#endif

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_OPENSSLCA_CA_H
