 /* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */
#include <src_generated/ua_types_generated.h>
#include <ua_types.h>
#include "ua_registration_manager.h"
#include "server/ua_server_internal.h"
#include "server/ua_services.h"
#ifdef UA_ENABLE_GDS


/*
    UA_NodeId applicationId;
    UA_String applicationUri; xxx
    UA_ApplicationType applicationType; xxx
    size_t applicationNamesSize; xxx
    UA_LocalizedText *applicationNames; xxx
    UA_String productUri; xxx
    size_t discoveryUrlsSize;
    UA_String *discoveryUrls;
    size_t serverCapabilitiesSize;
    UA_String *serverCapabilities;
*/


//TODO replacement for string localhost in discoveryurl
 // TODO malloc may fail: return a statuscode
UA_StatusCode GDS_registerApplication(UA_Server *server,
                                      UA_ApplicationRecordDataType *input,
                                      size_t certificateGroupSize,
                                      UA_NodeId *certificateGroupIds,
                                      UA_NodeId *output) {
     size_t index = 0;
     gds_registeredServer_entry *newEntry = (gds_registeredServer_entry *)UA_malloc(sizeof(gds_registeredServer_entry));
     UA_ApplicationRecordDataType *record = &newEntry->gds_registeredServer;
     UA_ApplicationRecordDataType_init(record);

     //ApplicationUri
     if (UA_String_equal(&input->applicationUri, &UA_STRING_NULL)) {
         goto error;
     }
     record->applicationUri.length = input->applicationUri.length;
     record->applicationUri.data = (UA_Byte *) malloc(input->applicationUri.length * sizeof(UA_Byte));
     memcpy(record->applicationUri.data, input->applicationUri.data,input->applicationUri.length);

     //check and set ApplicationType
     if (input->applicationType != UA_APPLICATIONTYPE_SERVER
         && input->applicationType != UA_APPLICATIONTYPE_CLIENT
         && input->applicationType != UA_APPLICATIONTYPE_DISCOVERYSERVER) {
         goto error;
     }
     record->applicationType = input->applicationType;

     //ApplicationNames
     if(input->applicationNamesSize <= 0) {
         goto error;
     }

     record->applicationNamesSize = input->applicationNamesSize;
     record->applicationNames = (UA_LocalizedText *)
             UA_calloc(record->applicationNamesSize, sizeof(UA_LocalizedText));
     while(index < input->applicationNamesSize) {
         if(UA_String_equal(&input->applicationNames[index].locale, &UA_STRING_NULL)
            || UA_String_equal(&input->applicationNames[index].text, &UA_STRING_NULL)) {
             goto error;
         }
         UA_LocalizedText_init(&record->applicationNames[index]);

         size_t locale_length = input->applicationNames[index].locale.length;
         record->applicationNames[index].locale.length = locale_length;
         record->applicationNames[index].locale.data = (UA_Byte *) malloc(locale_length * sizeof (UA_Byte));
         memcpy(record->applicationNames[index].locale.data, input->applicationNames[index].locale.data, locale_length);

         size_t text_length = input->applicationNames[index].text.length;
         record->applicationNames[index].text.length = text_length;
         record->applicationNames[index].text.data = (UA_Byte *) malloc(text_length * sizeof (UA_Byte));
         memcpy(record->applicationNames[index].text.data, input->applicationNames[index].text.data, text_length);

         index++;
     }

     //ProductUri
     if (UA_String_equal(&input->productUri, &UA_STRING_NULL)) {
         goto error;
     }
     record->productUri.length = input->productUri.length;
     record->productUri.data = (UA_Byte *) malloc(input->productUri.length * sizeof(UA_Byte));
     memcpy(record->productUri.data, input->productUri.data, input->productUri.length);


     //DiscoveryUrls
     //For servers it is mandatory to specify at least one discoveryUrl.
     //For Clients it is only required if they support reverse connect TODO(inv+ as prefix)
     if(record->applicationType != UA_APPLICATIONTYPE_CLIENT && input->discoveryUrlsSize <= 0) {
         goto error;
     }

     if (input->discoveryUrlsSize > 0) {
         index = 0;
         record->discoveryUrlsSize = input->discoveryUrlsSize;
         record->discoveryUrls = (UA_String *)
                 UA_calloc(record->discoveryUrlsSize, sizeof(UA_String));
         while(index < record->discoveryUrlsSize) {
             if (UA_String_equal(&input->discoveryUrls[index], &UA_STRING_NULL)) {
                 goto error;
             }
             UA_String_init(&record->discoveryUrls[index]);

             size_t discoveryLength = input->discoveryUrls[index].length;
             record->discoveryUrls[index].length = discoveryLength;
             record->discoveryUrls[index].data =
                     (UA_Byte *) malloc(discoveryLength * sizeof(UA_Byte));
             memcpy(record->discoveryUrls[index].data, input->discoveryUrls[index].data, discoveryLength);

             index++;
         }
     }

     //ServerCapabilities
     if(record->applicationType != UA_APPLICATIONTYPE_CLIENT && input->serverCapabilitiesSize <= 0) {
         goto error;
     }

     if (input->serverCapabilitiesSize > 0) {
         index = 0;
         record->serverCapabilitiesSize = input->serverCapabilitiesSize;
         record->serverCapabilities = (UA_String *)
                 UA_calloc(record->serverCapabilitiesSize, sizeof(UA_String));
         while(index < record->serverCapabilitiesSize) {
             if (UA_String_equal(&input->serverCapabilities[index], &UA_STRING_NULL)) {
                 goto error;
             }
             UA_String_init(&record->serverCapabilities[index]);

             size_t capLength = input->serverCapabilities[index].length;
             record->serverCapabilities[index].length = capLength;
             record->serverCapabilities[index].data =
                     (UA_Byte *) malloc(capLength * sizeof(UA_Byte));
             memcpy(record->serverCapabilities[index].data, input->serverCapabilities[index].data, capLength);

             index++;
         }
     }

     //CertificateGroup
     if (certificateGroupSize > 0) {
         index = 0;
         newEntry->certificateGroupSize = certificateGroupSize;
         newEntry->certificateGroups = (UA_NodeId *)
                 UA_calloc(certificateGroupSize, sizeof(UA_NodeId));
         while(index < certificateGroupSize) {
             memcpy(&newEntry->certificateGroups[index], &certificateGroupIds[index], sizeof(UA_NodeId));
             index++;
         }
     }

     record->applicationId = UA_NODEID_GUID(2, UA_Guid_random());
     *output = record->applicationId;
     LIST_INSERT_HEAD(&server->gds_registeredServers_list, newEntry, pointers);
     server->gds_registeredServersSize++;

     return UA_STATUSCODE_GOOD;

error: //Can be probably replaced with UA_ApplicationRecordDataType_deleteMembers
     UA_String_deleteMembers(&record->applicationUri);

     if (record->applicationNames != NULL) {
         index = 0;
         while (index < record->applicationNamesSize) {
             if (!UA_String_equal(&record->applicationNames[index].locale, &UA_STRING_NULL)) {
                 UA_String_deleteMembers(&record->applicationNames[index].locale);
             }
             if (!UA_String_equal(&record->applicationNames[index].text, &UA_STRING_NULL)) {
                 UA_String_deleteMembers(&record->applicationNames[index].text);
             }index++;
         }
         UA_free(record->applicationNames);
     }

     UA_String_deleteMembers(&record->productUri);

     if (record->discoveryUrls != NULL) {
         index = 0;
         while (index < record->discoveryUrlsSize) {
             if (!UA_String_equal(&record->discoveryUrls[index], &UA_STRING_NULL)) {
                 UA_String_deleteMembers(&record->discoveryUrls[index]);
             }
             index++;
         }
         UA_free(record->discoveryUrls);
     }

     if (record->serverCapabilities != NULL) {
         index = 0;
         while (index < record->serverCapabilitiesSize) {
             if (!UA_String_equal(&record->serverCapabilities[index], &UA_STRING_NULL)) {
                 UA_String_deleteMembers(&record->serverCapabilities[index]);
             }
             index++;
         }
         UA_free(record->serverCapabilities);
     }

     UA_free(record);
     return UA_STATUSCODE_BADINVALIDARGUMENT;
}

UA_StatusCode GDS_findApplication(UA_Server *server,
                                     UA_String *applicationUri,
                                     size_t *outputSize,
                                     UA_ApplicationRecordDataType **output) {

    /* Temporarily store all the pointers which we found to avoid reiterating
     * through the list */
    if (server->gds_registeredServersSize > 0) {
        size_t foundServersSize = 0;
        UA_STACKARRAY(UA_ApplicationRecordDataType*, gds_foundServers, server->gds_registeredServersSize);
        gds_registeredServer_entry* current;
        LIST_FOREACH(current, &server->gds_registeredServers_list, pointers) {
            if(UA_String_equal(&current->gds_registeredServer.applicationUri, applicationUri)) {
                gds_foundServers[foundServersSize] = &current->gds_registeredServer;
                foundServersSize++;
            }
        }
        *outputSize = foundServersSize;
        if (foundServersSize > 0) {
            *output = (UA_ApplicationRecordDataType *) UA_calloc(foundServersSize, sizeof(UA_ApplicationRecordDataType));
            for(size_t i = 0; i < foundServersSize; i++) {
                memcpy(output[i], gds_foundServers[i], sizeof(UA_ApplicationRecordDataType));
                i++;
            }
        }
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode GDS_unregisterApplication(UA_Server *server,
                                        UA_NodeId *nodeId) {
    gds_registeredServer_entry *gds_rs, *gds_rs_tmp;
    LIST_FOREACH_SAFE(gds_rs, &server->gds_registeredServers_list, pointers, gds_rs_tmp) {
        if(UA_NodeId_equal(&gds_rs->gds_registeredServer.applicationId, nodeId)) {
            LIST_REMOVE(gds_rs, pointers);
            UA_ApplicationRecordDataType_deleteMembers(&gds_rs->gds_registeredServer);
            if(gds_rs->certificateGroupSize > 0)
                UA_free(gds_rs->certificateGroups);
            UA_free(gds_rs);
            server->gds_registeredServersSize--;
        }
    }
    return UA_STATUSCODE_GOOD;
}

void GDS_deleteMembers(UA_Server *rm) {
    printf("\nIN\n");
    gds_registeredServer_entry *gds_rs, *gds_rs_tmp;
    LIST_FOREACH_SAFE(gds_rs, &rm->gds_registeredServers_list, pointers, gds_rs_tmp) {
        LIST_REMOVE(gds_rs, pointers);
        UA_ApplicationRecordDataType_deleteMembers(&gds_rs->gds_registeredServer);
        if(gds_rs->certificateGroupSize > 0)
            UA_free(gds_rs->certificateGroups);
        UA_free(gds_rs);
        rm->gds_registeredServersSize--;
    }
}

#endif /* UA_ENABLE_GDS */