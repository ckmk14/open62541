/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include "ua_certificate_manager.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_GDS

#define UA_GDS_CM_CHECK_MALLOC(pointer) \
                    if (!pointer) {    \
                        UA_LOG_WARNING(server->config.logger, UA_LOGCATEGORY_SERVER, "malloc failed"); \
                        return UA_STATUSCODE_BADOUTOFMEMORY; \
                    }

#define UA_GDS_CM_CHECK_ALLOC(errorcode) \
                    if (errorcode) {    \
                        UA_LOG_WARNING(server->config.logger, UA_LOGCATEGORY_SERVER, "malloc failed"); \
                        return errorcode; \
                    }
static
void delete_CertificateManager_entry(gds_cm_entry *newEntry){
    if (!UA_ByteString_equal(&newEntry->certificate, &UA_BYTESTRING_NULL))
        UA_ByteString_deleteMembers(&newEntry->certificate);

    if (!UA_ByteString_equal(&newEntry->privateKey, &UA_BYTESTRING_NULL))
        UA_ByteString_deleteMembers(&newEntry->privateKey);

    if (newEntry->issuerCertificateSize > 0){
        size_t index = 0;
        while (index < newEntry->issuerCertificateSize){
            if (!UA_ByteString_equal(&newEntry->issuerCertificates[index],&UA_BYTESTRING_NULL))
                UA_ByteString_deleteMembers(&newEntry->issuerCertificates[index]);
            index++;
        }
        UA_ByteString_delete(newEntry->issuerCertificates);
    }

    UA_free(newEntry);
}

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
    if (UA_NodeId_equal(applicationId,&UA_NODEID_NULL))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    GDS_CA *ca = server->config.gds_certificateGroups[0].ca; //DefaultApplicationGroup
    gds_cm_entry *newEntry = (gds_cm_entry *)UA_calloc(1, sizeof(gds_cm_entry));
 //   UA_GDS_CM_CHECK_MALLOC(newEntry);


    UA_StatusCode retval = ca->createNewKeyPair(ca, subjectName,
                         privateKeyFormat, privateKeyPassword,
                         2048, domainNameSize, domainNames,
                         &newEntry->certificate, &newEntry->privateKey,
                         &newEntry->issuerCertificateSize, &newEntry->issuerCertificates);

    if (retval == UA_STATUSCODE_GOOD){
        *requestId = newEntry->requestId = UA_NODEID_GUID(2, UA_Guid_random());
        printf("RequestID: " UA_PRINTF_GUID_FORMAT "\n",
               UA_PRINTF_GUID_DATA(requestId->identifier.guid));
        newEntry->applicationId = *applicationId;
        newEntry->isApproved = UA_TRUE;
        LIST_INSERT_HEAD(&server->certificateManager.gds_cm_list, newEntry, pointers);
        server->certificateManager.counter++;
/*
        FILE *f = fopen("/home/kocybi/hope.der", "w");
        fwrite(newEntry->certificate.data, newEntry->certificate.length, 1, f);
        fclose(f);

        FILE *f2 = fopen("/home/kocybi/hope2.der", "w");
        fwrite(newEntry->privateKey.data, newEntry->privateKey.length, 1, f2);
        fclose(f2);

        FILE *f3 = fopen("/home/kocybi/hope3.der", "w");
        fwrite(newEntry->issuerCertificates[0].data, newEntry->issuerCertificates[0].length, 1, f3);
        fclose(f3);
*/
    }
    else {
        delete_CertificateManager_entry(newEntry);
    }
    return retval;
}

UA_StatusCode
GDS_StartSigningRequest(UA_Server *server,
                        UA_NodeId *applicationId,
                        UA_NodeId *certificateGroupId,
                        UA_NodeId *certificateTypeId,
                        UA_ByteString *certificateRequest,
                        UA_NodeId *requestId){

    GDS_CA *ca = server->config.gds_certificateGroups[0].ca;

    gds_cm_entry *newEntry = (gds_cm_entry *)UA_calloc(1, sizeof(gds_cm_entry));
    UA_GDS_CM_CHECK_MALLOC(newEntry);

    UA_StatusCode retval = ca->certificateSigningRequest(ca, 0, certificateRequest,
                                  &newEntry->certificate,
                                  &newEntry->issuerCertificateSize,
                                  &newEntry->issuerCertificates);

    if (retval == UA_STATUSCODE_GOOD){
        *requestId = newEntry->requestId = UA_NODEID_GUID(2, UA_Guid_random());
        printf("RequestID: " UA_PRINTF_GUID_FORMAT "\n",
               UA_PRINTF_GUID_DATA(requestId->identifier.guid));
        newEntry->applicationId = *applicationId;
        newEntry->isApproved = UA_TRUE;
        newEntry->privateKey = UA_BYTESTRING_NULL;
        LIST_INSERT_HEAD(&server->certificateManager.gds_cm_list, newEntry, pointers);
        server->certificateManager.counter++;
    }
    else {
        delete_CertificateManager_entry(newEntry);
    };

    return retval;
}


UA_StatusCode
GDS_FinishRequest(UA_Server *server,
                  UA_NodeId *applicationId,
                  UA_NodeId *requestId,
                  UA_ByteString *certificate,
                  UA_ByteString *privKey,
                  size_t *length,
                  UA_ByteString **issuerCertificate) {
    gds_cm_entry *entry, *entry_tmp;
    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    LIST_FOREACH_SAFE(entry, &server->certificateManager.gds_cm_list, pointers, entry_tmp) {
       if (UA_NodeId_equal(&entry->requestId, requestId)
           && UA_NodeId_equal(&entry->applicationId, applicationId)
           && entry->isApproved) {
           ret = UA_ByteString_allocBuffer(certificate, entry->certificate.length);
           UA_GDS_CM_CHECK_ALLOC(ret);
           memcpy(certificate->data, entry->certificate.data, entry->certificate.length);

           if (!UA_ByteString_equal(&entry->privateKey, &UA_BYTESTRING_NULL)) {
               UA_ByteString_allocBuffer(privKey, entry->privateKey.length);
               memcpy(privKey->data, entry->privateKey.data, entry->privateKey.length);
           }

           *length = entry->issuerCertificateSize;
           size_t index = 0;
           *issuerCertificate = (UA_ByteString *)
                   UA_calloc (entry->issuerCertificateSize, sizeof(UA_ByteString));
           UA_GDS_CM_CHECK_MALLOC(*issuerCertificate);
           while (index < entry->issuerCertificateSize) {
               ret = UA_ByteString_allocBuffer(issuerCertificate[index],
                                         entry->issuerCertificates[index].length);
               UA_GDS_CM_CHECK_ALLOC(ret);
               memcpy(issuerCertificate[index]->data,
                      entry->issuerCertificates[index].data,
                      entry->issuerCertificates[index].length);
               index++;
           }
           return ret;

       }
    }
    return UA_STATUSCODE_BADINVALIDARGUMENT;
}


UA_StatusCode
GDS_GetCertificateGroups(UA_Server *server,
                         UA_NodeId *applicationId,
                         size_t *outputSize,
                         UA_NodeId **certificateGroupIds) {
    if (server->gds_registeredServersSize > 0) {
        gds_registeredServer_entry* current;
        LIST_FOREACH(current, &server->gds_registeredServers_list, pointers) {
            if(UA_NodeId_equal(&current->gds_registeredServer.applicationId, applicationId)) {
                if (current->certificateGroupSize){
                    *outputSize = current->certificateGroupSize;
                    *certificateGroupIds =
                            (UA_NodeId *) UA_calloc(current->certificateGroupSize, sizeof(UA_NodeId));
                    UA_GDS_CM_CHECK_MALLOC(*certificateGroupIds);
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
    gds_cm_entry *gds_rs, *gds_rs_tmp;
    LIST_FOREACH_SAFE(gds_rs, &server->certificateManager.gds_cm_list, pointers, gds_rs_tmp) {
        LIST_REMOVE(gds_rs, pointers);
        UA_ByteString_deleteMembers(&gds_rs->certificate);
        UA_ByteString_deleteMembers(&gds_rs->privateKey);
        size_t index = 0;
        while (index < gds_rs->issuerCertificateSize) {
            UA_ByteString_deleteMembers(&gds_rs->issuerCertificates[index]);
            index++;
        }
        UA_ByteString_delete(gds_rs->issuerCertificates);
        server->certificateManager.counter--;
        UA_free(gds_rs);
    }
    return UA_STATUSCODE_GOOD;

}

UA_StatusCode
GDS_CertificateManager_init(UA_Server *server) {
    LIST_INIT(&server->certificateManager.gds_cm_list);
    server->certificateManager.counter = 0;
    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_GDS */