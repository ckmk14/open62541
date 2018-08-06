/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_GDS_NS_H
#define OPEN62541_UA_GDS_NS_H


#ifdef __cplusplus
extern "C" {
#endif


#include "ua_types.h"
#include "ua_plugin_log.h"
#include "ua_log_stdout.h"
#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_GDS /* conditional compilation */

UA_StatusCode UA_Server_InitGdsNamspace(UA_Server *server);

#endif

#ifdef __cplusplus
} // extern "C"
#endif
#endif //OPEN62541_UA_GDS_NS_H
