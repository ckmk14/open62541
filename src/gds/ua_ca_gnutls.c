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
    if(gnuErr < 0) {                                                       \
        UA_LOG_GNUERR                                                  \
        ret = errorcode;                                             \
    }

#define UA_GNUTLS_ERRORHANDLING_RETURN(errorcode)                      \
    if(gnuErr < 0) {                                                       \
        UA_LOG_GNUERR                                                  \
        return errorcode;                                               \
    }


typedef struct {
    gnutls_x509_crt_t ca_crt;
    gnutls_x509_privkey_t ca_key;
    int serialNumber;
} CaContext;


static void deleteMembers_gnutls(GDS_CAPlugin *cg) {
    if(cg == NULL)
        return;

    if(cg->context == NULL)
        return;

    CaContext *cc = (CaContext *) cg->context;

    gnutls_x509_crt_deinit(cc->ca_crt);
    gnutls_x509_privkey_deinit(cc->ca_key);
    gnutls_global_deinit();
    UA_free(cc);
    cg->context = NULL;
}


static UA_StatusCode generate_private_key(GDS_CAPlugin *scg,
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

static UA_StatusCode create_caContext(GDS_CAPlugin *scg,
                                      UA_String caName,
                                      unsigned int caDays,
                                      int serialNumber,
                                      unsigned int caBitKeySize,
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
    int gnuErr = gnutls_x509_crt_init (&cc->ca_crt);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    ret = generate_private_key(scg, &cc->ca_key, caBitKeySize);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_dn (cc->ca_crt, (char *) caName.data, NULL);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_key(cc->ca_crt, cc->ca_key);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnutls_x509_crt_set_version(cc->ca_crt, 3);

    cc->serialNumber = serialNumber;
    gnuErr = gnutls_x509_crt_set_serial(cc->ca_crt, &cc->serialNumber, sizeof(int));
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    //TODO: This might be an issue (using time.h)
    gnuErr = gnutls_x509_crt_set_activation_time(cc->ca_crt, time(NULL));
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_expiration_time(cc->ca_crt, time(NULL) + caDays);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;


    unsigned char buff[20];
    size_t size = sizeof(buff);
    gnuErr = gnutls_x509_crt_get_key_id(cc->ca_crt, 0, buff, &size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;


    gnuErr = gnutls_x509_crt_set_subject_key_id (cc->ca_crt, buff, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;


    gnuErr = gnutls_x509_crt_set_authority_key_id (cc->ca_crt, buff, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto error;

    gnuErr = gnutls_x509_crt_set_ca_status (cc->ca_crt, 1);
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

   //   save_x509(cc->ca_crt, "/home/kocybi/ca.der");
//
//    unsigned char buffer[10 * 1024];
//    size_t buffer_size = sizeof(buffer);
//    gnutls_x509_privkey_export(cc->ca_key, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
//
//    FILE *f = fopen("/home/kocybi/ca_priv.der", "w");
//    fwrite(buffer, buffer_size, 1, f);
//    fclose(f);

    return UA_STATUSCODE_GOOD;

error:
    UA_LOG_ERROR(scg->logger, UA_LOGCATEGORY_SECURITYPOLICY, "Could not create CaContext");
    if(scg->context!= NULL)
        deleteMembers_gnutls(scg);
    return ret;
}


//Only for test purposes, this code will be necessary for the server side to generate a CSR
//So this is useful code
// TODO Error handling for CSR
void UA_createCSR(GDS_CAPlugin *scg, UA_ByteString *csr) {
    gnutls_x509_crq_t crq;
    gnutls_x509_privkey_t key;
    unsigned char buffer[10 * 1024];
    size_t buffer_size = sizeof(buffer);

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
    gnutls_x509_crq_export(crq, GNUTLS_X509_FMT_DER, buffer, &buffer_size);

    UA_ByteString_allocBuffer(csr, buffer_size + 1);
    memcpy(csr->data, buffer, buffer_size);
    csr->data[buffer_size] = '\0';
    csr->length--;

    unsigned char buf[10 * 1024];
    size_t buf_size = sizeof(buf);
    gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_DER, buf, &buf_size);

    FILE *f = fopen("/home/kocybi/app_priv.der", "w");
    fwrite(buf, buf_size, 1, f);
    fclose(f);

    gnutls_x509_crq_deinit(crq);
    gnutls_x509_privkey_deinit(key);
}


static UA_StatusCode setCommonCertificateFields(GDS_CAPlugin *scg, gnutls_x509_crt_t *cert) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    int gnuErr = gnutls_x509_crt_set_version(*cert, 3);
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    //TODO using time.h might be an issue
    gnuErr = gnutls_x509_crt_set_activation_time(*cert, time(NULL));
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    //TODO check if expiration time with ca certificate
    gnuErr = gnutls_x509_crt_set_expiration_time(*cert, time(NULL) + (60 * 60 * 24 * 365 * 5));
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    gnuErr = gnutls_x509_crt_set_ca_status (*cert, 0);
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    gnuErr = gnutls_x509_crt_set_key_usage(*cert,
                                           GNUTLS_KEY_DIGITAL_SIGNATURE
                                           | GNUTLS_KEY_NON_REPUDIATION
                                           | GNUTLS_KEY_DATA_ENCIPHERMENT
                                           | GNUTLS_KEY_KEY_ENCIPHERMENT );

    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    gnuErr = gnutls_x509_crt_set_key_purpose_oid (*cert, GNUTLS_KP_TLS_WWW_SERVER, 0);
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    gnuErr = gnutls_x509_crt_set_key_purpose_oid (*cert, GNUTLS_KP_TLS_WWW_CLIENT, 0);
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    return ret;
}


//TODO csr_gnutls check key size within csr
static UA_StatusCode csr_gnutls(GDS_CAPlugin *scg,
                         const UA_ByteString *certificateSigningRequest,
                         unsigned int supposedKeySize,
                         UA_ByteString *const certificate) {

    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    if(scg == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    CaContext *cc = (CaContext *) scg->context;

    gnutls_x509_crq_t crq;
    gnutls_x509_crt_t cert;

    gnutls_datum_t data = {NULL, 0};
    data.data = certificateSigningRequest->data;
    data.size = (unsigned int) certificateSigningRequest->length ;

    int gnuErr = gnutls_x509_crq_init(&crq);
    if (gnuErr < 0) {
        gnutls_x509_crq_deinit(crq);
        UA_LOG_GNUERR;
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    gnuErr = gnutls_x509_crt_init(&cert);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADOUTOFMEMORY);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    gnuErr = gnutls_x509_crq_import(crq, &data, GNUTLS_X509_FMT_DER);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    //verify signature of CSR
    gnuErr = gnutls_x509_crq_verify(crq, 0);
    if (GNUTLS_E_PK_SIG_VERIFY_FAILED == gnuErr) {
        ret = UA_STATUSCODE_BADREQUESTNOTALLOWED;
        goto deinit_csr;
    }

    //Create Certificate
    // TODO: DN currently in CSR, not sure if this is always the case (Check .NET GDS)
    gnuErr = gnutls_x509_crt_set_crq(cert, crq);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    //    char bufferDN[1024];
    //    size_t bufferDN_size = sizeof(bufferDN);
    //    gnuErr = gnutls_x509_crq_get_dn(crq, bufferDN, &bufferDN_size);
    //    gnuErr = gnutls_x509_crt_set_dn (cert, bufferDN, NULL);

    //TODO: overflow possible
    int serialNumber = cc->serialNumber + 1;
    gnuErr = gnutls_x509_crt_set_serial(cert, &serialNumber, sizeof(int));
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    ret = setCommonCertificateFields(scg, &cert);
    if (ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;


    unsigned char buf[20]; // SHA-1 with 20 bytes
    size_t size = sizeof(buf);
    gnuErr = gnutls_x509_crq_get_key_id(crq, 0, buf, &size );
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    gnuErr = gnutls_x509_crt_set_subject_key_id (cert, buf, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    size = sizeof(buf);
    gnuErr = gnutls_x509_crt_get_key_id(cc->ca_crt, 0, buf, &size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    gnuErr = gnutls_x509_crt_set_authority_key_id(cert, buf, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_csr;

    //get SAN from CSR
    unsigned int index = 0;
    char buffer[1024 * 10];
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
        if(ret != UA_STATUSCODE_GOOD)
            goto deinit_csr;
        buffer_size = sizeof(buffer); //important otherwise there are parsing issues
        index++;
    }

    gnuErr = gnutls_x509_crt_sign2(cert, cc->ca_crt, cc->ca_key, GNUTLS_DIG_SHA256, 0);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    //Export certificate
    memset(buffer, 0, sizeof(buffer));
    buffer_size = sizeof(buffer);
    gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, buffer, &buffer_size);
    UA_ByteString_allocBuffer(certificate, buffer_size + 1);
    memcpy(certificate->data, buffer, buffer_size);
    certificate->data[buffer_size] = '\0';
    certificate->length--;

    save_x509(cert, "/home/kocybi/app.der");
deinit_csr:
    gnutls_x509_crq_deinit(crq);
    gnutls_x509_crt_deinit(cert);

    return ret;
}




//TODO insufficient detection - this has to be improved
static
gnutls_x509_subject_alt_name_t detectSubjectAltName(UA_String *name) {
    char *str = (char *) name->data;

    if (strncmp("urn:", str, 4) == 0)
        return GNUTLS_SAN_URI;

    struct sockaddr_in sa;
    if (inet_pton(AF_INET, str, &(sa.sin_addr)))
        return GNUTLS_SAN_IPADDRESS;

    return GNUTLS_SAN_DNSNAME;
}

//TODO implement privateKey password
//TODO implement pfx support for private key, right now only pem is implemented (part12/p.34)
//example for pfx generation: https://www.gnutls.org/manual/gnutls.html#PKCS12-structure-generation-example
static UA_StatusCode createNewKeyPair_gnutls (GDS_CAPlugin *scg,
                                   UA_String *subjectName,
                                   UA_String *privateKeyFormat,
                                   UA_String *privateKeyPassword,
                                   unsigned  int keySize,
                                   size_t domainNamesSize,
                                   UA_String *domainNamesArray,
                                   UA_ByteString *const certificate,
                                   UA_ByteString *const privateKey,
                                   size_t *issuerCertificateSize,
                                   UA_ByteString **issuerCertificates) {


    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    UA_String subjectName_nullTerminated;

    if(scg == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    CaContext *cc = (CaContext *) scg->context;

    gnutls_x509_crt_t cert;
    gnutls_x509_privkey_t privkey;
    int gnuErr = gnutls_x509_crt_init(&cert);
    if (gnuErr < 0) {
        gnutls_x509_crt_deinit(cert);
        UA_LOG_GNUERR;
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    ret = generate_private_key(scg, &privkey, keySize);
    if (ret != UA_STATUSCODE_GOOD){
        return ret;
    }

    unsigned char buffer[10 * 1024];
    size_t buf_size = sizeof(buffer);
    gnuErr = gnutls_x509_privkey_export(privkey, GNUTLS_X509_FMT_DER, buffer, &buf_size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    UA_ByteString_allocBuffer(privateKey, buf_size + 1 );
    memcpy(privateKey->data, buffer, buf_size);
    privateKey->data[buf_size] = '\0';
    privateKey->length--;

    //gnutls_x509_crt_set_dn requires null terminated string
    subjectName_nullTerminated.length = subjectName->length + 1;
    subjectName_nullTerminated.data = (UA_Byte *)
            UA_calloc(subjectName_nullTerminated.length, sizeof(UA_Byte));
    memcpy(subjectName_nullTerminated.data, subjectName->data, subjectName->length);
    subjectName_nullTerminated.length--;

    gnuErr = gnutls_x509_crt_set_dn(cert, (char *) subjectName_nullTerminated.data, NULL);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    gnuErr = gnutls_x509_crt_set_key(cert, privkey);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    //TODO: overflow possible
    int serialNumber = cc->serialNumber + 1;
    gnuErr = gnutls_x509_crt_set_serial(cert, &serialNumber, sizeof(int));
    UA_GNUTLS_ERRORHANDLING_RETURN(UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    ret = setCommonCertificateFields(scg, &cert);
    if (ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    unsigned char buf[20]; // SHA-1 with 20 bytes
    size_t size = sizeof(buf);
    gnuErr = gnutls_x509_privkey_get_key_id(privkey,0, buf, &size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    gnuErr = gnutls_x509_crt_set_subject_key_id (cert, buf, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    size = sizeof(buf);
    gnuErr = gnutls_x509_crt_get_key_id(cc->ca_crt, 0, buf, &size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    gnuErr = gnutls_x509_crt_set_authority_key_id(cert, buf, size);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    for (size_t i = 0; i < domainNamesSize; i++) {

        UA_String san_nullTerminated;
        san_nullTerminated.length = domainNamesArray[i].length + 1;
        san_nullTerminated.data = (UA_Byte *)
                UA_calloc(san_nullTerminated.length, sizeof(UA_Byte));
        memcpy(san_nullTerminated.data, domainNamesArray[i].data, domainNamesArray[i].length);
        san_nullTerminated.length--;

        gnutls_x509_subject_alt_name_t san =
                detectSubjectAltName(&san_nullTerminated);

        if (san == GNUTLS_SAN_IPADDRESS){
            struct sockaddr_in sa;
            inet_pton(AF_INET, (char *) san_nullTerminated.data, &(sa.sin_addr));

            gnuErr = gnutls_x509_crt_set_subject_alt_name (cert,
                                                           san,
                                                           &sa.sin_addr,
                                                           sizeof(sa.sin_addr),
                                                           GNUTLS_FSAN_APPEND);
        }
        else {

            gnuErr = gnutls_x509_crt_set_subject_alt_name (cert,
                                                           san,
                                                           domainNamesArray[i].data,
                                                           (unsigned int)domainNamesArray[i].length,
                                                           GNUTLS_FSAN_APPEND);

        }

        UA_String_deleteMembers(&san_nullTerminated);

        UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
        if(ret != UA_STATUSCODE_GOOD)
            goto deinit_create;
    }

    gnuErr = gnutls_x509_crt_sign2(cert, cc->ca_crt, cc->ca_key, GNUTLS_DIG_SHA256, 0);
    UA_GNUTLS_ERRORHANDLING(UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    if(ret != UA_STATUSCODE_GOOD)
        goto deinit_create;

    //Export certificate
    memset(buffer, 0, sizeof(buffer));
    buf_size = sizeof(buffer);
    gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, buffer, &buf_size);
    UA_ByteString_allocBuffer(certificate, buf_size + 1);
    memcpy(certificate->data, buffer, buf_size);
    certificate->data[buf_size] = '\0';
    certificate->length--;

    save_x509(cert, "/home/kocybi/app2.der");

    //Export issuer certificate
    *issuerCertificateSize = 1;
    *issuerCertificates = (UA_ByteString *) UA_calloc(sizeof(UA_ByteString), *issuerCertificateSize);
    memset(buffer, 0, sizeof(buffer));
    buf_size = sizeof(buffer);
    gnutls_x509_crt_export(cc->ca_crt, GNUTLS_X509_FMT_DER, buffer, &buf_size);
    UA_ByteString_allocBuffer(*issuerCertificates, buf_size + 1);
    memcpy((*issuerCertificates)[0].data, buffer, buf_size);
    (*issuerCertificates)[0].data[buf_size] = '\0';
    (*issuerCertificates)[0].length--;
    save_x509(cc->ca_crt, "/home/kocybi/ca2.der");


deinit_create:
    if (!UA_String_equal(&subjectName_nullTerminated, &UA_STRING_NULL)) {
        UA_String_deleteMembers(&subjectName_nullTerminated);
    }
    gnutls_x509_crt_deinit(cert);
    gnutls_x509_privkey_deinit(privkey);
    return ret;

}

UA_StatusCode UA_InitCA(GDS_CAPlugin *scg,
                        UA_String caName,
                        unsigned int caDays,
                        int sn,
                        unsigned int caBitKeySize,
                        UA_Logger logger) {
    memset(scg, 0, sizeof(GDS_CAPlugin));
    scg->logger = logger;
    scg->certificateSigningRequest = csr_gnutls;
    scg->createNewKeyPair = createNewKeyPair_gnutls;
    scg->deleteMembers = deleteMembers_gnutls;

    return create_caContext(scg, caName, caDays, sn, caBitKeySize, logger);
}



//static gnutls_datum_t load_file(const char *file) {
//    FILE *f;
//    gnutls_datum_t loaded_file = {NULL, 0};
//    long filelen;
//    void *ptr;
//
//    if (!(f = fopen(file, "r"))
//        || fseek(f, 0, SEEK_END) != 0
//        || (filelen = ftell(f)) < 0
//        || fseek(f, 0, SEEK_SET) != 0
//        || !(ptr = malloc((size_t) filelen))
//        || fread (ptr, 1, (size_t)filelen, f) < (size_t)filelen) {
//        return loaded_file;
//    }
//
//    loaded_file.data = (unsigned char *)ptr;
//    loaded_file.size = (unsigned int)filelen;
//    fclose(f);
//    return loaded_file;
//}
//
//static void unload_file(gnutls_datum_t data) {
//    free(data.data);
//}

//void UA_test(UA_GDSCertificateGroup *scg){
//    FILE *f;
//    gnutls_datum_t crtdata = {NULL, 0};
//    long filelen;
//    void *ptr;
//
//    if (!(f = fopen("/home/kocybi/uaexpert.der", "r"))
//        || fseek(f, 0, SEEK_END) != 0
//        || (filelen = ftell(f)) < 0
//        || fseek(f, 0, SEEK_SET) != 0
//        || !(ptr = malloc((size_t) filelen))
//        || fread (ptr, 1, (size_t)filelen, f) < (size_t)filelen) {
//        printf("Error\n");
//    }
//
//    crtdata.data = (unsigned char*) ptr;
//    crtdata.size = (unsigned int)filelen;
//    fclose(f);
//
//
//    gnutls_x509_crt_t ua_cert;
//    gnutls_x509_crt_init(&ua_cert);
//
//    int gnuErr = gnutls_x509_crt_import(ua_cert, &crtdata, GNUTLS_X509_FMT_DER);
//
//    gnutls_pubkey_t pp;
//    gnuErr = gnutls_pubkey_init(&pp);
//    gnuErr = gnutls_pubkey_import_x509(pp, ua_cert, 0);
//
//    unsigned char buffer[10 * 1024];
//    size_t buffer_size = sizeof(buffer);
//    gnuErr = gnutls_pubkey_export(pp, GNUTLS_X509_FMT_DER, buffer, &buffer_size);
//
//
// //   gnutls_datum_t tt = {NULL, 0};
//  //  tt.data = (unsigned char*) buffer;
//  //  tt.size = (unsigned int)buffer_size;
//
//
// //   unsigned char test3[20];
// //   size_t size3 = sizeof(test3);
// //   gnuErr = gnutls_x509_crt_get_subject_key_id(ua_cert, test3, &size3,0);
//
//    //gnuErr = gnutls_fingerprint(GNUTLS_DIG_SHA1, &tt, test3, &size3 );
//
//    ///////////////////////////////////
//
//    gnutls_privkey_t pk;
//    gnutls_privkey_init(&pk);
//    gnuErr = gnutls_privkey_generate(pk,GNUTLS_PK_RSA, 2048, 0);
//    gnutls_x509_crt_t crt;
//    gnutls_x509_privkey_t privKey;
//    gnutls_x509_crt_init(&crt);
//    gnuErr = gnutls_privkey_export_x509(pk, &privKey);
//    gnuErr = gnutls_x509_crt_set_dn (crt, "O=test,CN=test", NULL);
//    gnuErr = gnutls_x509_crt_set_key(crt, privKey);
//    gnutls_x509_crt_set_version(crt, 3);
//    int serialNumber = rand();
//    gnuErr = gnutls_x509_crt_set_serial(crt, &serialNumber, sizeof(int));
//
//    //Here is the problem
//  //  unsigned char test[20];
// //   size_t size = sizeof(test);
////    gnuErr = gnutls_pubkey_get_key_id(pp, 0, test, &size);
//    gnuErr = gnutls_x509_crt_set_subject_key_id(crt, test3, size3 );
//
//
//
///////////////////////////////////////////////////////////////////
//    gnuErr = gnutls_x509_crt_set_key_usage(crt,
//                                           GNUTLS_KEY_DIGITAL_SIGNATURE
//                                           | GNUTLS_KEY_CRL_SIGN
//                                           | GNUTLS_KEY_KEY_CERT_SIGN);
//
//    gnuErr = gnutls_x509_crt_set_activation_time(crt, time(NULL));
//    gnuErr = gnutls_x509_crt_set_expiration_time(crt, time(NULL) + (60 * 60 * 24 * 365 * 10));
//
//    gnuErr = gnutls_x509_crt_sign2(crt, crt, privKey, GNUTLS_DIG_SHA256, 0);
//
//    save_x509(crt, "/home/kocybi/test2.cert");
//
////    unsigned char buffer[10 * 1024];
////    size_t buffer_size = sizeof(buffer);
////    gnutls_x509_privkey_export(privKey, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
////
////    f = fopen("/home/kocybi/priv2.der", "w");
////    fwrite(buffer, buffer_size, 1, f);
////    fclose(f);
//
//    printf("%u", gnuErr);
//
//}
#endif