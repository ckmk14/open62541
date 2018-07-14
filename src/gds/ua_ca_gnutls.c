/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include "ua_ca_gnutls.h"
#include <gnutls/x509.h>
#include <ua_types.h>

#ifdef UA_ENABLE_GDS


#define UA_LOG_GNUERR                                                  \
    UA_LOG_WARNING(scg->logger, UA_LOGCATEGORY_SERVER, \
                   "gnuTLS returned an error: %s", gnutls_strerror(gnuErr));           \

#define UA_GNUTLS_ERRORHANDLING(errorcode)                             \
    if(gnuErr) {                                                       \
        UA_LOG_GNUERR                                                  \
        ret = errorcode;                                             \
    }

#define UA_GNUTLS_ERRORHANDLING_RETURN(errorcode)                      \
    if(gnuErr) {                                                       \
        UA_LOG_GNUERR                                                  \
        return errorcode;                                               \
    }

typedef struct {
    gnutls_x509_crt_t ca_crt;
    gnutls_x509_privkey_t ca_key;
} CaContext;

static void deleteMembers_gnutls(UA_GDSCertificateGroup *cg) {
    if(cg == NULL)
        return;

    if(cg->context == NULL)
        return;

    CaContext *cc = (CaContext *) cg->context;

    gnutls_x509_crt_deinit(cc->ca_crt);
    gnutls_x509_privkey_deinit(cc->ca_key);

    UA_free(cc);
    cg->context = NULL;
}


static UA_StatusCode generate_private_key_int(UA_GDSCertificateGroup *scg,
                                              gnutls_x509_privkey_t *privKey,
                                              unsigned int bits) {

    int gnuErr = gnutls_x509_privkey_init(privKey);
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADOUTOFMEMORY);

    gnuErr = gnutls_x509_privkey_generate(*privKey, GNUTLS_PK_RSA, bits, 0);
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADINTERNALERROR);

    return UA_STATUSCODE_GOOD;
}



static void save_x509(gnutls_x509_crt_t crt, const char *loc) {
    gnutls_datum_t crtdata = {0};
    gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_DER, NULL, (size_t*)&crtdata.size);
    crtdata.data = (unsigned char *) malloc(crtdata.size);
    gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_DER, crtdata.data, (size_t*)&crtdata.size);
    FILE *f = fopen(loc, "w");
    fwrite(crtdata.data, crtdata.size, 1, f);
    fclose(f);
    free(crtdata.data);

}

static UA_StatusCode create_caContext(UA_GDSCertificateGroup *scg,
                                      UA_String caName,
                                      UA_Logger logger) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    if(scg == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    CaContext *cc = (CaContext *) UA_malloc(sizeof(CaContext));
    scg->context = (void *)cc;
    if(!cc) {
        ret = UA_STATUSCODE_BADOUTOFMEMORY;
        goto error;
    }

    /* Initialize the CaContext */
    memset(cc, 0, sizeof(CaContext));
    gnutls_x509_crt_init (&cc->ca_crt);
    generate_private_key_int(scg, &cc->ca_key, 2048);

    int gnuErr = gnutls_x509_crt_set_dn (cc->ca_crt, (char *) caName.data, NULL);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_key(cc->ca_crt, cc->ca_key);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnutls_x509_crt_set_version(cc->ca_crt, 3);

    int crt_serial = rand();
    gnutls_x509_crt_set_serial(cc->ca_crt, &crt_serial, sizeof(int));

    //This might be an issue
    gnuErr = gnutls_x509_crt_set_activation_time(cc->ca_crt, time(NULL));
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_expiration_time(cc->ca_crt, time(NULL) + (60 * 60 * 24 * 365 * 10));
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    unsigned char buf[20] = {0}; // Normally 20 bytes (SHA1)
    size_t size = 0;
    gnutls_x509_crt_get_key_id(cc->ca_crt, 0, buf, &size);
    gnuErr = gnutls_x509_crt_set_subject_key_id (cc->ca_crt, buf, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_ca_status (cc->ca_crt, 1);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_authority_key_id(cc->ca_crt, buf, size); //self signed
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_key_usage(cc->ca_crt,
                                           GNUTLS_KEY_DIGITAL_SIGNATURE
                                           | GNUTLS_KEY_CRL_SIGN
                                           | GNUTLS_KEY_KEY_CERT_SIGN);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_sign2(cc->ca_crt, cc->ca_crt, cc->ca_key, GNUTLS_DIG_SHA256, 0);
    if(gnuErr != UA_STATUSCODE_GOOD)
        goto error;

    save_x509(cc->ca_crt, "/home/markus/test.cert");

    return UA_STATUSCODE_GOOD;

error:
    UA_LOG_ERROR(scg->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Could not create CaContext");
    if(scg->context!= NULL)
        deleteMembers_gnutls(scg);
    return ret;
}


UA_StatusCode UA_InitCA(UA_GDSCertificateGroup *scg, UA_String caName, UA_Logger logger) {
    memset(scg, 0, sizeof(UA_GDSCertificateGroup));
    scg->logger = logger;
    scg->deleteMembers = deleteMembers_gnutls;

    return create_caContext(scg, caName, logger);
}

#endif