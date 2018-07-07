/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include "ua_trustlist.h"
#include <gnutls/x509.h>



UA_StatusCode UA_InitTrustList(UA_TrustList *tl,
                                         const UA_ByteString *trustList,  size_t trustListSize,
                                         const UA_ByteString *trustedCrl, size_t trustedCrlsSize,
                                         UA_Logger logger){


    return UA_STATUSCODE_GOOD;
}
