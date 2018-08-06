/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_PLUGIN_REGISTRATION_MANAGER_H
#define OPEN62541_UA_PLUGIN_REGISTRATION_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_types.h"
#include "ua_plugin_log.h"
#include "queue.h"

#ifdef UA_ENABLE_GDS

typedef struct gds_registeredServer_entry {
    UA_ApplicationRecordDataType gds_registeredServer;
    LIST_ENTRY(gds_registeredServer_entry) pointers;
} gds_registeredServer_entry;

struct UA_GDSRegistrationManager;
typedef struct UA_GDSRegistrationManager UA_GDSRegistrationManager;

LIST_HEAD(gds_list, gds_registeredServer_entry) gds_registeredServers_list;

struct UA_GDSRegistrationManager {
    UA_Logger logger;

    UA_StatusCode (*registerApplication)(UA_GDSRegistrationManager *rm,
                                         UA_ApplicationRecordDataType *record,
                                         UA_NodeId *newNodeId);

    void (*deleteMembers)(UA_GDSRegistrationManager *rm);
};

#endif

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_PLUGIN_REGISTRATION_MANAGER_H
