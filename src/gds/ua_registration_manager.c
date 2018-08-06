/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */
#include <src_generated/ua_types_generated.h>
#include <ua_types.h>
#include "ua_registration_manager.h"

#ifdef UA_ENABLE_GDS

static UA_StatusCode registerApplication(UA_GDSRegistrationManager *rm,
                                         UA_ApplicationRecordDataType *input,
                                         UA_NodeId *output) {
    printf("\nIn RegisterCallback\n");
    UA_ApplicationRecordDataType record;
    UA_ApplicationRecordDataType_init(&record);
    UA_ApplicationRecordDataType_copy(&record, input);

    gds_registeredServer_entry *newEntry =
            (gds_registeredServer_entry *)UA_malloc(sizeof(gds_registeredServer_entry));
    //UA_ApplicationRecordDataType_copy(&newEntry->gds_registeredServer, input);

    UA_ApplicationRecordDataType_init(&newEntry->gds_registeredServer);
    newEntry->gds_registeredServer.applicationUri = UA_STRING("Test");

    LIST_INSERT_HEAD(&gds_registeredServers_list, newEntry, pointers);

    *output = record.applicationId = UA_NODEID_GUID(2, UA_Guid_random());

    return UA_STATUSCODE_GOOD;
}


static void deleteMembers(UA_GDSRegistrationManager *rm) {
    printf("\nIN\n");
    gds_registeredServer_entry *gds_rs, *gds_rs_tmp;
    LIST_FOREACH_SAFE(gds_rs, &gds_registeredServers_list, pointers, gds_rs_tmp) {
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