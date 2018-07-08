/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_TRUSTLIST_H
#define OPEN62541_UA_TRUSTLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_plugin_trustlist.h"

UA_EXPORT UA_StatusCode UA_InitTrustList(UA_TrustList *tl,
                                        const char* pathToTrustListDir,
                                        const char* pathToTrustCrlsDir,
                                        UA_Logger logger);

#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_TRUSTLIST_H
