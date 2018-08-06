 /* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */
#include <src_generated/ua_types_generated.h>
#include <ua_types.h>
#include "ua_registration_manager.h"

#ifdef UA_ENABLE_GDS
//TODO replacement for string localhost
static UA_StatusCode registerApplication(UA_ApplicationRecordDataType *input,
                                         UA_NodeId *output) {
     printf("\nIn RegisterCallback\n");

    // Check the input, probably more cases to consider   //      || !input->productUri.length
     //      || !input->applicationNamesSize) {
     if (!input->applicationUri.length) {
         return UA_STATUSCODE_BADINVALIDARGUMENT;
     }

     size_t index = 0;
     while(index < input->applicationNamesSize) {
         if(!input->applicationNames[index].locale.length
            || !input->applicationNames[index].text.length){
             return UA_STATUSCODE_BADINVALIDARGUMENT;
        }
        index++;
     }

     gds_registeredServer_entry *newEntry = (gds_registeredServer_entry *)UA_malloc(sizeof(gds_registeredServer_entry));
     UA_ApplicationRecordDataType *record = &newEntry->gds_registeredServer;
     UA_ApplicationRecordDataType_init(record);
     record->applicationUri.length = input->applicationUri.length;
     record->applicationUri.data = (UA_Byte *) malloc(input->applicationUri.length * sizeof(UA_Byte));
     memcpy(record->applicationUri.data, input->applicationUri.data,input->applicationUri.length);

     LIST_INSERT_HEAD(&gds_registeredServers_list, newEntry, pointers);
     *output = UA_NODEID_GUID(2, UA_Guid_random());

     return UA_STATUSCODE_GOOD;
}


static void deleteMembers(UA_GDSRegistrationManager *rm) {
    printf("\nIN\n");
    gds_registeredServer_entry *gds_rs, *gds_rs_tmp;
    LIST_FOREACH_SAFE(gds_rs, &gds_registeredServers_list, pointers, gds_rs_tmp) {
        printf("\nIN2\n");
        UA_String_deleteMembers(&gds_rs->gds_registeredServer.applicationUri);
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