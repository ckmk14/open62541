/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include <src_generated/ua_types_generated.h>
#include "ua_certificate_manager.h"

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
                           UA_String *privateKeyPassword,
                           UA_NodeId *requestId) {
    GDS_CAPlugin *ca = server->config.gds_certificateGroups[0].ca;

    UA_ByteString cert;
    UA_ByteString passw;

    UA_String name3 = UA_STRING("urn:unconfigured:application");
    ca->createNewKeyPair(ca, subjectName, NULL, NULL, 2048, domainNameSize, domainNames, &name3, &cert, &passw);

    UA_ByteString_deleteMembers(&cert);
    UA_ByteString_deleteMembers(&passw);
    return UA_STATUSCODE_BADINVALIDARGUMENT;
}

UA_StatusCode
GDS_GetCertificateGroups(UA_Server *server, UA_NodeId *applicationId, size_t *outputSize, UA_NodeId **certificateGroupIds) {
    if (server->gds_registeredServersSize > 0) {
        gds_registeredServer_entry* current;
        LIST_FOREACH(current, &server->gds_registeredServers_list, pointers) {
            if(UA_NodeId_equal(&current->gds_registeredServer.applicationId, applicationId)) {
                if (current->certificateGroupSize){
                    *outputSize = current->certificateGroupSize;
                    *certificateGroupIds =
                            (UA_NodeId *) UA_calloc(current->certificateGroupSize, sizeof(UA_NodeId));
                    memcpy(*certificateGroupIds,
                           current->certificateGroups,
                           sizeof(UA_NodeId) * current->certificateGroupSize);
                    break;
                }
            }
        }
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
GDS_CertificateManager_close(UA_Server *server){
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
GDS_CertificateManager_init(UA_Server *server) {
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_GDS */