/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */


#ifndef OPEN62541_UA_REGISTRATION_MANAGER_H
#define OPEN62541_UA_REGISTRATION_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "gds/ua_plugin_registration_manager.h"
#include "ua_plugin_log.h"

#ifdef UA_ENABLE_GDS

UA_EXPORT UA_StatusCode UA_InitGDSRegistrationManager(UA_GDSRegistrationManager *rm);

#endif /* UA_ENABLE_GDS */

#ifdef __cplusplus
}
#endif


#endif //OPEN62541_UA_REGISTRATION_MANAGER_H
