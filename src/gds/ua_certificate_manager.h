/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_CERTIFICATE_MANAGER_H
#define OPEN62541_UA_CERTIFICATE_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_plugin_log.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_GDS


UA_StatusCode
GDS_StartNewKeyPairRequest(UA_Server *server,
                           UA_NodeId *applicationId,
                           UA_NodeId *certificateGroupId,
                           UA_NodeId *certificateTypeId,
                           UA_String *subjectName,
                           size_t  domainNameSize,
                           UA_String *domainNames,
                           UA_String *privateKeyFormat,
                           UA_String *privateKeyPassword);

UA_StatusCode
GDS_GetCertificateGroups(UA_Server *server,
                     UA_NodeId *applicationId,
                     size_t *outputSize,
                     UA_NodeId **certificateGroupIds);


#endif /* UA_ENABLE_GDS */

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_CERTIFICATE_MANAGER_H
