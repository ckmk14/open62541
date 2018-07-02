//
// Created by markus on 23.06.18.
//

#ifndef OPEN62541_UA_PLUGIN_CA_H
#define OPEN62541_UA_PLUGIN_CA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_types.h"
#include "ua_plugin_log.h"

struct UA_GDSCertificateGroup;
typedef struct UA_GDSCertificateGroup UA_GDSCertificateGroup;

struct UA_GDSCertificateGroup {
    void *CAContext;
    UA_Logger logger;
    UA_StatusCode (*certificateSigningRequest)(UA_GDSCertificateGroup *scg,
                                       const UA_ByteString *csr,
                                       UA_ByteString *const certificate);
    UA_StatusCode (*createNewKeyPair) (UA_GDSCertificateGroup *scg, UA_String subjectName,
                                       UA_String *privateKeyFormat,
                                       UA_String *privateKeyPassword,
                                       const UA_String *domainNames,
                                       size_t domainNamesSize);

    UA_Boolean  (*isCertificatefromCA) (UA_GDSCertificateGroup *scg, UA_ByteString certificate);


    /* Kein mbedtls:https://github.com/ARMmbed/mbedtls/issues/459
     * The suggested API would be to extend the mbedtls_x509_sequence
     * subject_alt_names in mbedtls_x509_crt to contain all the names,
     * rather than stripping the non-dNSName ones.
     *
     * ADDCertToCRL
     * ADDCertToTrustList
     * ADDCertToIssuerList
     * RenewCACert
     * GetTrustList
     * GetIssuerList
     * GetCACertificate
     * GetCRL
     *
     * */
    void (*deleteMembers)(UA_GDSCertificateGroup *scg);
};


#ifdef __cplusplus
}
#endif

#endif //OPEN62541_UA_PLUGIN_CA_H
