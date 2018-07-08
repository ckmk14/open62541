/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include "ua_trustlist.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <ua_types.h>


static void deleteMembers_gnutls(UA_TrustList *tl){
    if(tl == NULL)
        return;

    for(size_t i = 0; i < tl->trustListSize; i++)
        UA_ByteString_deleteMembers(&tl->trustedCertificates[i]);

    if (tl->trustListSize > 0){
        UA_free(tl->trustedCertificates);
        tl->trustedCertificates = NULL;
    }

    UA_LOG_DEBUG(tl->logger, UA_LOGCATEGORY_SERVER, "Deleted members of TrustList");
}


static void createTrustList(UA_TrustList *tl, gnutls_x509_trust_list_t trustList){

    gnutls_x509_trust_list_iter_t trust_iter = NULL;
    gnutls_x509_crt_t get_ca_crt;
    gnutls_datum_t get_datum;

    tl->trustedCertificates = (UA_ByteString *)
            UA_malloc(tl->trustListSize * sizeof (UA_ByteString));

    size_t n_get_ca_crts = 0;
    while (gnutls_x509_trust_list_iter_get_ca(trustList, &trust_iter, &get_ca_crt) !=
           GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        int ret = gnutls_x509_crt_export2(get_ca_crt, GNUTLS_X509_FMT_DER, &get_datum);
        if (ret < 0)
            UA_LOG_ERROR(tl->logger, UA_LOGCATEGORY_SERVER, "GnuTLS could not export Certificate");

        time_t activation_time;
        activation_time = gnutls_x509_crt_get_activation_time (get_ca_crt);
        printf ("\tCertificate is valid since: %s", ctime (&activation_time));

        tl->trustedCertificates[n_get_ca_crts].length = get_datum.size;
        tl->trustedCertificates[n_get_ca_crts].data = (UA_Byte *)UA_malloc(get_datum.size * sizeof(UA_Byte));
        memcpy(tl->trustedCertificates[n_get_ca_crts].data, get_datum.data, get_datum.size);

        gnutls_x509_crt_deinit(get_ca_crt);
        gnutls_free(get_datum.data);

        ++n_get_ca_crts;
    }

    if (n_get_ca_crts != tl->trustListSize)
        UA_LOG_ERROR(tl->logger, UA_LOGCATEGORY_SERVER, "GnuTLS: n_cas != tl->trustListSize");
}

static size_t addCertificateToGnuTLSTrustList(UA_TrustList *tl,
                                              gnutls_x509_trust_list_t *gnutls_tl,
                                              UA_ByteString *certificate) {
    gnutls_x509_crt_t cert;
    gnutls_datum_t data = {NULL, 0};
    data.data = certificate->data;
    data.size = (unsigned int) certificate->length ;
    gnutls_x509_crt_init(&cert);
    int ret = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_DER);
    if (ret != GNUTLS_E_SUCCESS)
        UA_LOG_ERROR(tl->logger, UA_LOGCATEGORY_SERVER, "GnuTLS could not import certificate");

    return (size_t) gnutls_x509_trust_list_add_cas(*gnutls_tl, &cert,(size_t) 1, GNUTLS_TL_NO_DUPLICATES);
}

static UA_StatusCode addCertificate_gnutls(UA_TrustList *tl, UA_ByteString *certificate) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if (tl == NULL || certificate == NULL)
        return retval;

    gnutls_x509_trust_list_t trustList;
    int ret = gnutls_x509_trust_list_init(&trustList, 0);
    if (ret != 0) {
        UA_LOG_ERROR(tl->logger, UA_LOGCATEGORY_SERVER, "GnuTLS could not create trustListContext");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    size_t n_get_ca_crts = 0;
    for(size_t i = 0; i < tl->trustListSize; i++){
        n_get_ca_crts += addCertificateToGnuTLSTrustList(tl, &trustList, &tl->trustedCertificates[i]);
        printf("\nAdded something%u", (int) n_get_ca_crts);
    }

    n_get_ca_crts += addCertificateToGnuTLSTrustList(tl, &trustList, certificate);

    if (n_get_ca_crts != tl->trustListSize + 1) {
        UA_LOG_WARNING(tl->logger, UA_LOGCATEGORY_SERVER, "GnuTLS could not add new certificate");
        return   UA_STATUSCODE_GOOD;
    }
    deleteMembers_gnutls(tl);

    tl->trustListSize += 1;
    createTrustList(tl, trustList);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode createGnuTLSTrustList(UA_TrustList *tl,
                                            const char* pathToTrustListDir,
                                            const char* pathToTrustCrlsDir) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    gnutls_x509_trust_list_t trustList;
    int ret = gnutls_x509_trust_list_init(&trustList, 0);
    if (ret != 0) {
        UA_LOG_ERROR(tl->logger, UA_LOGCATEGORY_SERVER, "GnuTLS could not create trustListContext");
        goto error;
    }

    tl->trustListSize += (size_t) gnutls_x509_trust_list_add_trust_dir(trustList,
                                         pathToTrustListDir,
                                         pathToTrustCrlsDir,
                                         GNUTLS_X509_FMT_DER,
                                         GNUTLS_TL_NO_DUPLICATES, 0);

    printf("Added %u Certificates", (int )tl->trustListSize);

    if (tl->trustListSize  > 0)
        createTrustList(tl, trustList);

    //TODO: Implement CRL stuff

    gnutls_x509_trust_list_deinit(trustList, 1);

    return retval;

error:
    UA_LOG_ERROR(tl->logger, UA_LOGCATEGORY_SERVER, "Could not create trustListContext");
    deleteMembers_gnutls(tl);
    return retval;
}


UA_StatusCode UA_InitTrustList(UA_TrustList *tl,
                               const char* pathToTrustListDir,
                               const char* pathToTrustCrlsDir,
                               UA_Logger logger){

    tl->trustListSize = 0;
    tl->trustedCrlsSize = 0;
    tl->trustedCertificates = NULL;
    tl->trustedCrls = NULL;

    tl->logger = logger;
    tl->addCertificate = addCertificate_gnutls;
    tl->deleteMembers = deleteMembers_gnutls;

    return createGnuTLSTrustList(tl, pathToTrustListDir, pathToTrustCrlsDir);
}
