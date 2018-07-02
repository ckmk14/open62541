//
// Created by markus on 23.06.18.
//

#include "ua_opensslCA_ca.h"
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define  CA_KEY_USAGE "critical,digitalSignature,keyCertSign,cRLSign"
#define  CA_BASIC_CONSTRAINTS "critical,CA:TRUE"
#define  CA_SUBJECT_KEY_IDENTIFIER "hash"
#define  CA_ISSUER_KEY_IDENTIFIER "keyid:always,issuer:always"

typedef struct {
    X509 *caCert;
    EVP_PKEY *caKey;
} CAContext;

static void deleteMembers_GDSCertificateGroup(UA_GDSCertificateGroup *scg){
    if(scg == NULL)
        return;

    if(scg->CAContext == NULL)
        return;

    CAContext *cac = (CAContext *) scg->CAContext;

    EVP_PKEY_free(cac->caKey);
    X509_free(cac->caCert);

    UA_free(cac);
    scg->CAContext = NULL;
}
void smth(void);
 void smth() {
    const char cert_filestr[] = "cert.pem";
    BIO              *certbio = NULL;
    BIO               *outbio = NULL;
    X509                *cert = NULL;
    X509_CINF       *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) *ext_list;
    int ret, i;

    /* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
     * Load the certificate from file (PEM).                      *
     * ---------------------------------------------------------- */
    ret = (int) BIO_read_filename(certbio, cert_filestr);
    if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        exit(-1);
    }

    /* ---------------------------------------------------------- *
     * Extract the certificate's extensions                       *
     * ---------------------------------------------------------- */
    cert_inf = cert->cert_info;

    ext_list = cert_inf->extensions;

    if(sk_X509_EXTENSION_num(ext_list) <= 0) return;

    /* ---------------------------------------------------------- *
     * Print the extension value                                  *
     * ---------------------------------------------------------- */
    for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
        ASN1_OBJECT *obj;
        X509_EXTENSION *ext;

        ext = sk_X509_EXTENSION_value(ext_list, i);

        obj = X509_EXTENSION_get_object(ext);
        BIO_printf(outbio, "\n");
        BIO_printf(outbio, "Object %.2d: ", i);
        i2a_ASN1_OBJECT(outbio, obj);
        BIO_printf(outbio, "\n");

        X509V3_EXT_print(outbio, ext, 0, 0);
        BIO_printf(outbio, "\n");
    }

    X509_free(cert);
    BIO_free_all(certbio);
    BIO_free_all(outbio);
    return;
}

static int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}


static UA_StatusCode Create_CAContext(UA_GDSCertificateGroup *scg,
                                      int privateKeySize,
                                      size_t privateKeyExponent,
                                      char *CommonName,
                                      char *Organisation,
                                      char *Country,
                                      int days) {

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(scg == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;


    CAContext *cac = (CAContext*)malloc(sizeof(CAContext));
    scg->CAContext = (void *) cac;
    if(!cac) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto error;
    }


    memset(cac, 0, sizeof(CAContext));
    cac->caKey = EVP_PKEY_new();
    if(!cac->caKey)
        goto error;

    RSA *rsa = RSA_generate_key(privateKeySize, privateKeyExponent, NULL, NULL);

    //RSA structure will be automatically freed when the EVP_PKEY structure is freed
    EVP_PKEY_assign_RSA(cac->caKey, rsa);

    cac->caCert = X509_new();

    X509_set_version(cac->caCert,2);
    ASN1_INTEGER_set(X509_get_serialNumber(cac->caCert), 1);
    X509_gmtime_adj(X509_get_notBefore(cac->caCert), 0);
    X509_gmtime_adj(X509_get_notAfter(cac->caCert),(long)60*60*24*days);

    X509_set_pubkey(cac->caCert, cac->caKey);
    X509_NAME *name = X509_get_subject_name(cac->caCert);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *) Country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *) Organisation, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) CommonName, -1, -1, 0);

    X509_set_issuer_name(cac->caCert, name);

    add_ext(cac->caCert, NID_basic_constraints, CA_BASIC_CONSTRAINTS);
    add_ext(cac->caCert, NID_key_usage, CA_KEY_USAGE);
    add_ext(cac->caCert, NID_subject_key_identifier, CA_SUBJECT_KEY_IDENTIFIER);
    add_ext(cac->caCert, NID_authority_key_identifier,CA_ISSUER_KEY_IDENTIFIER);

    X509_sign(cac->caCert, cac->caKey, EVP_sha256());

    FILE * f;
    f = fopen("cert.pem", "wb");
    PEM_write_X509(f, cac->caCert);
    fclose(f);

  //  smth();
    return retval;

error:
    UA_LOG_ERROR(scg->logger, UA_LOGCATEGORY_SERVER, "Could not create CAContext");
    if(scg->CAContext != NULL)
        deleteMembers_GDSCertificateGroup(scg);
    return UA_STATUSCODE_BADINTERNALERROR;
}

static int do_X509_sign(X509 *cert, EVP_PKEY *pkey, const EVP_MD *md)
{
    int rv;
    EVP_MD_CTX mctx;
    EVP_PKEY_CTX *pkctx = NULL;

    EVP_MD_CTX_init(&mctx);
    rv = EVP_DigestSignInit(&mctx, &pkctx, md, NULL, pkey);

    if (rv > 0)
        rv = X509_sign_ctx(cert, &mctx);
    EVP_MD_CTX_cleanup(&mctx);
    return rv > 0 ? 1 : 0;
}

static UA_StatusCode certificateSigningRequest (UA_GDSCertificateGroup *scg,
                                                const UA_ByteString *csr,
                                                UA_ByteString *const certificate) {

    CAContext *cac = (CAContext *)scg->CAContext;
    const char      *szUserCert = "/home/markus/open62541/cmake-build-debug/examples/cert.pem";
    FILE * f;
    f = fopen("/home/markus/open62541/cmake-build-debug/examples/example.csr", "r");

    X509_REQ        *req = NULL;
    if (!(req = PEM_read_X509_REQ (f, NULL, NULL, NULL)))
        printf("Error reading request in file");

    X509 *cert = X509_new();

    X509_set_version(cert,2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
    X509_set_issuer_name(cert, X509_get_subject_name(cac->caCert));

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*10);

    X509_NAME *subject = NULL, *tmpname = NULL;
    tmpname = X509_REQ_get_subject_name(req);
    subject = X509_NAME_dup(tmpname);
    X509_set_subject_name(cert, subject);

    EVP_PKEY *pkey = NULL, *pktmp = NULL;
    pktmp = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, pktmp);

    STACK_OF(X509_EXTENSION) *ext_list;
    ext_list = X509_REQ_get_extensions(req);


    if(sk_X509_EXTENSION_num(ext_list) <= 0) {
        printf("Nein");
    }
    else {
        printf("JA");
        int i;
        BUF_MEM *bptr = NULL;
        char *buf = NULL;
        for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
            ASN1_OBJECT *obj;
            X509_EXTENSION *ext;

            ext = sk_X509_EXTENSION_value(ext_list, i);

            BIO *bio = BIO_new(BIO_s_mem());
            if(!X509V3_EXT_print(bio, ext, 0, 0)){
                // error handling...
            }
            BIO_flush(bio);
            BIO_get_mem_ptr(bio, &bptr);

            buf = (char *)malloc( (bptr->length + 1)*sizeof(char) );

            memcpy(buf, bptr->data, bptr->length);
            buf[bptr->length] = '\0';
            add_ext(cert, NID_subject_alt_name, buf);
            printf ("%s\n", buf);
        }
    }


    EVP_PKEY_free(pktmp);

    do_X509_sign(cert, cac->caKey, EVP_sha256());

    BIO *out = NULL;
    out = BIO_new_file(szUserCert,"w");
    PEM_write_bio_X509(out, cert);

    BIO_free_all(out);
    fclose(f);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_CreateGDSCertificateGroup(UA_GDSCertificateGroup *scg, int privateKeySizeCA,
                             size_t privateKeyExponent, UA_Logger logger) {

    scg->logger = logger;
    scg->certificateSigningRequest = certificateSigningRequest;
    scg->deleteMembers = deleteMembers_GDSCertificateGroup;

    printf("Hallo");

    return Create_CAContext(scg, privateKeySizeCA, privateKeyExponent, "DEDE", "DE", "DE", 365);
}