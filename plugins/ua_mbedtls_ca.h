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

UA_EXPORT void UA_InitCA(UA_GDSCertificateGroup *scg, UA_Logger logger);

#endif

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_MBEDTLS_CA_H
