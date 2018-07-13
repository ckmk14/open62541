/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include "ua_ca_gnutls.h"
#include <gnutls/x509.h>

#ifdef UA_ENABLE_GDS

UA_StatusCode UA_InitCA(UA_GDSCertificateGroup *scg, UA_Logger logger){
    printf("\nIN\n");
    gnutls_x509_trust_list_t trustList;
    gnutls_x509_trust_list_init(&trustList, 0);
    gnutls_x509_trust_list_deinit(trustList, 1);
    return  UA_STATUSCODE_GOOD;
}

#endif