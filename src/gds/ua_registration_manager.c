 /* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */
#include <src_generated/ua_types_generated.h>
#include <ua_types.h>
#include "ua_registration_manager.h"

#ifdef UA_ENABLE_GDS


/*
    UA_NodeId applicationId;
    UA_String applicationUri;
    UA_ApplicationType applicationType;
    size_t applicationNamesSize;
    UA_LocalizedText *applicationNames;
    UA_String productUri;
    size_t discoveryUrlsSize;
    UA_String *discoveryUrls;
    size_t serverCapabilitiesSize;
    UA_String *serverCapabilities;

 * */


//TODO replacement for string localhost in discoveryurl
 // TODO malloc may fail: return a statuscode
static UA_StatusCode registerApplication(UA_ApplicationRecordDataType *input,
                                         UA_NodeId *output) {
     printf("\nIn RegisterCallback\n");

     gds_registeredServer_entry *newEntry = (gds_registeredServer_entry *)UA_malloc(sizeof(gds_registeredServer_entry));
     UA_ApplicationRecordDataType *record = &newEntry->gds_registeredServer;
     UA_ApplicationRecordDataType_init(record);

     //ApplicationUri
     if (input->applicationUri.length <= 0) {
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
         return UA_STATUSCODE_BADINVALIDARGUMENT;
     }

     size_t index = 0;
     record->applicationNamesSize = input->applicationNamesSize;
     record->applicationNames = (UA_LocalizedText *)
                                    malloc(record->applicationNamesSize *  sizeof(UA_LocalizedText));
     while(index < input->applicationNamesSize) {
         if(input->applicationNames[index].locale.length <= 0
            || input->applicationNames[index].text.length <= 0
            || input->applicationNames[index].locale.data == NULL
            || input->applicationNames[index].text.data == NULL){
             return UA_STATUSCODE_BADINVALIDARGUMENT;
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
     if(input->productUri.length <= 0) {
         return UA_STATUSCODE_BADINVALIDARGUMENT;
     }
     record->productUri.length = input->productUri.length;
     record->productUri.data = (UA_Byte *) malloc(input->productUri.length * sizeof(UA_Byte));
     memcpy(record->productUri.data, input->productUri.data, input->productUri.length);


     //DiscoveryUrls
     //For servers it is mandatory to specify at least one discoveryUrl.
     //For Clients it is only required if they support reverse connect TODO(inv+ as prefix)
     if(record->applicationType != UA_APPLICATIONTYPE_CLIENT && input->discoveryUrlsSize <= 0) {
         return UA_STATUSCODE_BADINVALIDARGUMENT;
     }

     if (input->discoveryUrlsSize > 0) {
         index = 0;
         record->discoveryUrlsSize = input->discoveryUrlsSize;
         record->discoveryUrls = (UA_String *)
                 malloc(record->discoveryUrlsSize *  sizeof(UA_String));
         while(index < record->discoveryUrlsSize) {
             if (input->discoveryUrls[index].length <= 0
                 || input->discoveryUrls[index].data == NULL) {
                 return UA_STATUSCODE_BADINVALIDARGUMENT;
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
         return UA_STATUSCODE_BADINVALIDARGUMENT;
     }

     if (input->serverCapabilitiesSize > 0) {
         index = 0;
         record->serverCapabilitiesSize = input->serverCapabilitiesSize;
         record->serverCapabilities = (UA_String *)
                 malloc(record->serverCapabilitiesSize *  sizeof(UA_String));
         while(index < record->serverCapabilitiesSize) {
             if (input->serverCapabilities[index].length <= 0
                 || input->serverCapabilities[index].data == NULL) {
                 return UA_STATUSCODE_BADINVALIDARGUMENT;
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

     LIST_INSERT_HEAD(&gds_registeredServers_list, newEntry, pointers);
     *output = UA_NODEID_GUID(2, UA_Guid_random());



     gds_registeredServer_entry *gds_rs, *gds_rs_tmp;
     LIST_FOREACH_SAFE(gds_rs, &gds_registeredServers_list, pointers, gds_rs_tmp) {
         printf("\nIN2\n");
     }

     return UA_STATUSCODE_GOOD;

error:
     if (!UA_String_equal(&record->applicationUri, &UA_STRING_NULL)){
        UA_String_deleteMembers(&record->applicationUri);
     }

     //TODO Tomorrow

     UA_free(record);
     return UA_STATUSCODE_BADINVALIDARGUMENT;
}


static void deleteMembers(UA_GDSRegistrationManager *rm) {
    printf("\nIN\n");
    gds_registeredServer_entry *gds_rs, *gds_rs_tmp;
    LIST_FOREACH_SAFE(gds_rs, &gds_registeredServers_list, pointers, gds_rs_tmp) {
        printf("\nIN2\n");
        UA_String_deleteMembers(&gds_rs->gds_registeredServer.applicationUri);
        UA_String_deleteMembers(&gds_rs->gds_registeredServer.productUri);
        size_t index = 0;
        while (index < gds_rs->gds_registeredServer.applicationNamesSize){
            UA_LocalizedText record = gds_rs->gds_registeredServer.applicationNames[index];
            UA_String_deleteMembers(&record.locale);
            UA_String_deleteMembers(&record.text);
            index++;
        }
        UA_free(gds_rs->gds_registeredServer.applicationNames);
        if (gds_rs->gds_registeredServer.discoveryUrlsSize > 0) {
            index = 0;
            while (index < gds_rs->gds_registeredServer.applicationNamesSize){
                UA_String record = gds_rs->gds_registeredServer.discoveryUrls[index];
                UA_String_deleteMembers(&record);
                index++;
            }
            UA_free(gds_rs->gds_registeredServer.discoveryUrls);
        }
        if(gds_rs->gds_registeredServer.serverCapabilitiesSize > 0) {
            index = 0;
            while (index < gds_rs->gds_registeredServer.serverCapabilitiesSize){
                UA_String record = gds_rs->gds_registeredServer.serverCapabilities[index];
                UA_String_deleteMembers(&record);
                index++;
            }
            UA_free(gds_rs->gds_registeredServer.serverCapabilities);
        }
        LIST_REMOVE(gds_rs, pointers);
        UA_free(gds_rs);
    }
}

UA_StatusCode UA_InitGDSRegistrationManager(UA_GDSRegistrationManager *rm){

    LIST_INIT(&gds_registeredServers_list);
    rm->registerApplication = registerApplication;
    rm->deleteMembers = deleteMembers;
    return UA_STATUSCODE_GOOD;
}

#endif