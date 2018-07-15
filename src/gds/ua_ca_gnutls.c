/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Markus Karch, Fraunhofer IOSB
 */

#include "ua_ca_gnutls.h"
#include <gnutls/x509.h>
#include "ua_types.h"
#include "libc_time.h"
#include <time.h>
#include <ua_types.h>
#include <gnutls/abstract.h>

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
    int serialNumber;
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


static UA_StatusCode generate_private_key(UA_GDSCertificateGroup *scg,
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
                                      unsigned int caDays,
                                      int serialNumber,
                                      UA_Logger logger) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    if(scg == NULL || serialNumber < 1)
        return UA_STATUSCODE_BADINTERNALERROR;

    CaContext *cc = (CaContext *) UA_malloc(sizeof(CaContext));
    scg->context = (void *)cc;
    if(!cc) {
        ret = UA_STATUSCODE_BADOUTOFMEMORY;
        goto error;
    }

    /* Initialize the CaContext */
    gnutls_global_init();
    memset(cc, 0, sizeof(CaContext));
    gnutls_x509_crt_init (&cc->ca_crt);
    generate_private_key(scg, &cc->ca_key, 2048);

    int gnuErr = gnutls_x509_crt_set_dn (cc->ca_crt, (char *) caName.data, NULL);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_key(cc->ca_crt, cc->ca_key);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnutls_x509_crt_set_version(cc->ca_crt, 3);

    cc->serialNumber = serialNumber;
    gnutls_x509_crt_set_serial(cc->ca_crt, &cc->serialNumber, sizeof(int));

    //TODO: This might be an issue (using time.h)
    gnuErr = gnutls_x509_crt_set_activation_time(cc->ca_crt, time(NULL));
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_expiration_time(cc->ca_crt, time(NULL) + caDays);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

/////////////////////////////////////////////////////////
    //TODO: there is something wrong

    


    //  gnutls_pubkey_t pubKey;

  //  unsigned char test[1024]; // Normally 20 bytes (SHA1)
  //  size_t size;
  //  gnuErr = gnutls_pubkey_import_privkey(pubKey, cc->ca_key,0,0);
   // gnuErr = gnutls_pubkey_get_key_id(pubKey, 0, test, &size);





//    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
//    if(ret != UA_STATUSCODE_GOOD)
//        goto error;
//
//    gnuErr = gnutls_x509_crt_set_subject_key_id (cc->ca_crt, buf, size);
//    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
//    if(ret != UA_STATUSCODE_GOOD)
//        goto error;



/////////////////////////////////////////////////////

//    gnuErr = gnutls_x509_crt_set_ca_status (cc->ca_crt, 1);
//    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
//    if(ret != UA_STATUSCODE_GOOD)
//        goto error;
//
//    gnuErr = gnutls_x509_crt_set_authority_key_id(cc->ca_crt, buf, size); //self signed
//    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
//    if(ret != UA_STATUSCODE_GOOD)
//        goto error;

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


void UA_createCSR(UA_GDSCertificateGroup *scg, UA_ByteString *csr) {
    printf("Hallo");

    gnutls_x509_crq_t crq;
    gnutls_x509_privkey_t key;
    unsigned char buffer[10 * 1024];
    size_t buffer_size = sizeof(buffer);

    gnutls_global_init();

    gnutls_x509_crq_init(&crq);
    generate_private_key(scg, &key, 2048);
    gnutls_x509_crq_set_version(crq, 1);

    gnutls_x509_crq_set_key(crq, key);

    UA_String name = UA_STRING("C=DE,O=open62541,CN=open62541Server@localhost");

    int gnuErr = gnutls_x509_crq_set_dn(crq, (char *) name.data, NULL);
    if (gnuErr)
        printf("\ngnuTLS returned an error: %s\n", gnutls_strerror(gnuErr));

    char * san1 = "localhost";
    gnuErr = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_DNSNAME,
                                                      san1, (unsigned int)strlen(san1), GNUTLS_FSAN_APPEND);
    if (gnuErr)
        printf("\ngnuTLS returned an error: %s\n", gnutls_strerror(gnuErr));

    char * san2 = "Q330";
    gnuErr = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_DNSNAME,
                                                      san2, (unsigned int)strlen(san2), GNUTLS_FSAN_APPEND);
    if (gnuErr)
        printf("\ngnuTLS returned an error: %s\n", gnutls_strerror(gnuErr));

    char * san3 = "urn:unconfigured:application";
    gnuErr = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_URI,
                                                  san3, (unsigned int)strlen(san3), GNUTLS_FSAN_APPEND);
    if (gnuErr)
        printf("\ngnuTLS returned an error: %s\n", gnutls_strerror(gnuErr));

    /* Self sign the certificate request.
     */
    gnutls_x509_crq_sign2(crq, key, GNUTLS_DIG_SHA1, 0);

    /* Export the PEM encoded certificate request, and display it.
     */
    gnutls_x509_crq_export(crq, GNUTLS_X509_FMT_DER, buffer, &buffer_size);

  //  printf("%u\n", (int)buffer_size);

  //  printf("Certificate Request: \n%s", buffer);

    UA_ByteString_allocBuffer(csr, buffer_size + 1);
    memcpy(csr->data, buffer, buffer_size);
    csr->data[buffer_size] = '\0';
    csr->length--;

    /* Export the PEM encoded private key, and
     * display it.
     */
   // buffer_size = sizeof(buffer);
    //gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM, buffer,
      //                         &buffer_size);

  //  printf("\n\nPrivate key: \n%s", buffer);

    gnutls_x509_crq_deinit(crq);
    gnutls_x509_privkey_deinit(key);
}

static UA_StatusCode csr_gnutls(UA_GDSCertificateGroup *scg,
                         const UA_ByteString *certificateSigningRequest,
                         UA_ByteString *const certificate) {

    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    if(scg == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    CaContext *cc = (CaContext *) scg->context;

    gnutls_x509_crq_t crq;
    gnutls_datum_t data = {NULL, 0};
    data.data = certificateSigningRequest->data;
    data.size = (unsigned int) certificateSigningRequest->length ;

    gnutls_x509_crq_init(&crq);
    gnutls_x509_crq_import(crq, &data, GNUTLS_X509_FMT_DER);

    //verify signature of CSR
    int gnuErr = gnutls_x509_crq_verify(crq, 0);
    if (GNUTLS_E_PK_SIG_VERIFY_FAILED == gnuErr)
        return UA_STATUSCODE_BADREQUESTNOTALLOWED;

    //Create Certificate
    gnutls_x509_crt_t cert;
    gnutls_x509_crt_init (&cert);

    // TODO: DN currently in CSR, not sure if this is always the case (Check .NET GDS)
    gnuErr = gnutls_x509_crt_set_crq(cert, crq);

//    char bufferDN[1024];
//    size_t bufferDN_size = sizeof(bufferDN);
//    gnuErr = gnutls_x509_crq_get_dn(crq, bufferDN, &bufferDN_size);
//    gnuErr = gnutls_x509_crt_set_dn (cert, bufferDN, NULL);

    gnutls_x509_crt_set_version(cert, 3);

    //TODO: overflow possible
    int serialNumber = cc->serialNumber + 1;
    gnuErr = gnutls_x509_crt_set_serial(cert, &serialNumber, sizeof(int));

    printf("\n%u\n", serialNumber);
    gnuErr = gnutls_x509_crt_set_activation_time(cert, time(NULL));
    gnuErr = gnutls_x509_crt_set_expiration_time(cert, time(NULL) + (60 * 60 * 24 * 365 * 5));

    gnuErr = gnutls_x509_crt_set_ca_status (cert, 0);

    gnuErr = gnutls_x509_crt_set_key_usage(cert,
                                           GNUTLS_KEY_DIGITAL_SIGNATURE
                                           | GNUTLS_KEY_NON_REPUDIATION
                                           | GNUTLS_KEY_DATA_ENCIPHERMENT
                                           | GNUTLS_KEY_KEY_ENCIPHERMENT );


    gnutls_x509_crt_set_key_purpose_oid (cert, GNUTLS_KP_TLS_WWW_SERVER, 0);
    gnutls_x509_crt_set_key_purpose_oid (cert, GNUTLS_KP_TLS_WWW_CLIENT, 0);

    //get SAN from CSR
    unsigned int index = 0;
    char buffer[1024];
    size_t buffer_size = sizeof(buffer);
    unsigned int sanType;
    unsigned int critical = 0;
    while (gnutls_x509_crq_get_subject_alt_name(crq, index, buffer,
                                                &buffer_size, &sanType, &critical)
            != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        gnuErr = gnutls_x509_crt_set_subject_alt_name (cert,
                                                       (gnutls_x509_subject_alt_name_t) sanType,
                                                        buffer,
                                                       (unsigned int) buffer_size,
                                                       GNUTLS_FSAN_APPEND);

        buffer_size = sizeof(buffer); //important otherwise there are parsing issues
        index++;
    }

    gnuErr = gnutls_x509_crt_sign2(cert, cc->ca_crt, cc->ca_key, GNUTLS_DIG_SHA256, 0);
    save_x509(cert, "/home/markus/app.cert");

    gnutls_x509_crt_deinit(cert);

    return ret;
}

UA_StatusCode UA_InitCA(UA_GDSCertificateGroup *scg, UA_String caName, unsigned int caDays, int sn, UA_Logger logger) {
    memset(scg, 0, sizeof(UA_GDSCertificateGroup));
    scg->logger = logger;
    scg->certificateSigningRequest = csr_gnutls;
    scg->deleteMembers = deleteMembers_gnutls;

    return create_caContext(scg, caName, caDays, sn,  logger);
}

#endif