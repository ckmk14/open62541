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

#include "ua_util_internal.h"
#include "ua_server.h"
#include "ua_plugin_ca.h"

#ifdef UA_ENABLE_GDS

typedef struct gds_cm_entry {
    LIST_ENTRY(gds_cm_entry) pointers;
    UA_NodeId requestId;
    UA_NodeId applicationId;
    UA_Boolean isApproved;
    UA_ByteString certificate;
    UA_ByteString privateKey;
    size_t issuerCertificateSize;
    UA_ByteString *issuerCertificates;
} gds_cm_entry;

typedef struct{
    LIST_HEAD(gds_cm__list, gds_cm_entry) gds_cm_list;
    size_t counter;
} GDS_CertificateManager;

UA_StatusCode
GDS_CertificateManager_init(UA_Server *server);

UA_StatusCode
GDS_FinishRequest(UA_Server *server,
                  UA_NodeId *applicationId,
                  UA_NodeId *requestId,
                  UA_ByteString *certificate,
                  UA_ByteString *privKey,
                  size_t *length,
                  UA_ByteString **issuerCertificate);

UA_StatusCode
GDS_StartNewKeyPairRequest(UA_Server *server,
                           UA_NodeId *applicationId,
                           UA_NodeId *certificateGroupId,
                           UA_NodeId *certificateTypeId,
                           UA_String *subjectName,
                           size_t  domainNameSize,
                           UA_String *domainNames,
                           UA_String *privateKeyFormat,
                           UA_String *privateKeyPassword,
                           UA_NodeId *requestId);

UA_StatusCode
GDS_GetCertificateGroups(UA_Server *server,
                         UA_NodeId *applicationId,
                         size_t *outputSize,
                         UA_NodeId **certificateGroupIds);

UA_StatusCode
GDS_CertificateManager_close(UA_Server *server);

#endif /* UA_ENABLE_GDS */

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_CERTIFICATE_MANAGER_H
