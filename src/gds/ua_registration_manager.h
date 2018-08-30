/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */


#ifndef OPEN62541_UA_REGISTRATION_MANAGER_H
#define OPEN62541_UA_REGISTRATION_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_plugin_log.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_GDS

UA_StatusCode
GDS_RegistrationManager_init(UA_Server *server);

UA_StatusCode
GDS_registerApplication(UA_Server *server, UA_ApplicationRecordDataType *input,
                        size_t certificateGroupSize, UA_NodeId *certificateGroupIds, UA_NodeId *output);
UA_StatusCode
GDS_findApplication(UA_Server *server, UA_String *applicationUri,
                    size_t *outputSize, UA_ApplicationRecordDataType **output);

UA_StatusCode
GDS_unregisterApplication(UA_Server *server, UA_NodeId *nodeId);

UA_StatusCode
GDS_RegistrationManager_close(UA_Server *rm);

#endif /* UA_ENABLE_GDS */

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_REGISTRATION_MANAGER_H
