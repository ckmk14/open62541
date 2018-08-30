/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_GDS_NS_H
#define OPEN62541_UA_GDS_NS_H


#ifdef __cplusplus
extern "C" {
#endif



#include "server/ua_server_internal.h"

#ifdef UA_ENABLE_GDS /* conditional compilation */

UA_StatusCode GDS_InitNamespace(UA_Server *server);

#endif

#ifdef __cplusplus
} // extern "C"
#endif
#endif //OPEN62541_UA_GDS_NS_H
