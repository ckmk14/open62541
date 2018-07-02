//
// Created by markus on 23.06.18.
//

#ifndef OPEN62541_UA_MBEDTLS_CA_H
#define OPEN62541_UA_MBEDTLS_CA_H

#include "ua_plugin_ca.h"
#include "ua_plugin_log.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef UA_ENABLE_CA

UA_EXPORT UA_StatusCode UA_CreateGDSCertificateGroup(UA_GDSCertificateGroup *scg,
                                                     int privateKeySizeCA,
                                                     size_t privateKeyExponent,
                                                     UA_Logger logger);

#endif

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_MBEDTLS_CA_H
