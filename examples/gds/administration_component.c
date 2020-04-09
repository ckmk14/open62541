/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */
/*
 * A simple server instance which registers with the discovery server (see server_lds.c).
 * Before shutdown it has to unregister itself.
 */

#include <open62541/plugin/log_stdout.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include "ua_record_datatype.h"
#include "ua_gds_client.h"
#include "common.h"

#define MIN_ARGS           3
#define FAILURE            1
#define CONNECTION_STRING1  "opc.tcp://localhost:4841"
#define CONNECTION_STRING2  "opc.tcp://localhost:4842"


UA_Boolean running = true;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}

int main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_Client*              gds_client         = NULL;
    UA_Client*              push_client        = NULL;
    UA_StatusCode           retval             = UA_STATUSCODE_GOOD;
    size_t                  trustListSize      = 0;
    UA_ByteString*          revocationList     = NULL;
    size_t                  revocationListSize = 0;


    if(argc < MIN_ARGS) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "The Certificate and key is missing."
                     "The required arguments are "
                     "<client-certificate.der> <client-private-key.der> "
                     "[<trustlist1.crl>, ...]");
        return FAILURE;
    }

    /* Load certificate and private key */
    UA_ByteString           certificate        = loadFile(argv[1]);
    UA_ByteString           privateKey         = loadFile(argv[2]);



    /* Load the trustList. Load revocationList is not supported now */
    if(argc > MIN_ARGS)
        trustListSize = (size_t)argc-MIN_ARGS;

    UA_STACKARRAY(UA_ByteString, trustList, trustListSize);
    for(size_t trustListCount = 0; trustListCount < trustListSize; trustListCount++) {
        trustList[trustListCount] = loadFile(argv[trustListCount+3]);
    }

    /* Secure client initialization for the communication with the GDS*/
    gds_client = UA_Client_new();
    UA_ClientConfig *gds_cc = UA_Client_getConfig(gds_client);
    UA_ClientConfig_setDefaultEncryption(gds_cc, certificate, privateKey, trustList, trustListSize, revocationList, revocationListSize);
    gds_cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;

    /* Secure client initialization - communication with server supporting push management*/
    push_client = UA_Client_new();
    UA_ClientConfig *push_cc = UA_Client_getConfig(push_client);
    UA_ClientConfig_setDefaultEncryption(push_cc, certificate, privateKey, trustList, trustListSize, revocationList, revocationListSize);
    push_cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;

    UA_DataTypeArray tmp = { gds_cc->customDataTypes, 1, &ApplicationRecordDataType};
    gds_cc->customDataTypes = &tmp;

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);

    for(size_t deleteCount = 0; deleteCount < trustListSize; deleteCount++)
        UA_ByteString_clear(&trustList[deleteCount]);

    if(gds_client == NULL || push_client == NULL) {
        return FAILURE;
    }

    /* Change the localhost to the IP running GDS if needed */
    retval = UA_Client_connect_username(gds_client, CONNECTION_STRING1, "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(gds_client);
        UA_Client_delete(push_client);
        return (int)retval;
    }

    /* A client to connect to the OPC UA server for pushing the certificate */
    retval = UA_Client_connect_username(push_client, CONNECTION_STRING2, "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(gds_client);
        UA_Client_delete(push_client);
        return (int)retval;
    }

    /* Every ApplicationURI shall be unique.
     * Therefore the client should be sure that the application is not registered yet. */
    UA_String applicationUri = UA_String_fromChars("urn:open62541.server.application");
    size_t length = 0;
    UA_ApplicationRecordDataType *records = NULL;
    UA_GDS_call_findApplication(gds_client, applicationUri, &length, records);

    if (!length) {
        // Register Application
        UA_NodeId appId = UA_NODEID_NULL;
        UA_ApplicationRecordDataType record;
        memset(&record, 0, sizeof(UA_ApplicationRecordDataType));
        record.applicationUri = applicationUri;
        record.applicationType = UA_APPLICATIONTYPE_SERVER;
        record.productUri = UA_STRING("urn:open62541.server.application");
        record.applicationNamesSize++;
        UA_LocalizedText applicationName = UA_LOCALIZEDTEXT("en-US", "open62541_Server");
        record.applicationNames = &applicationName;
        record.discoveryUrlsSize++;
        UA_String discoveryUrl = UA_STRING("opc.tcp://localhost:4842");
        record.discoveryUrls = &discoveryUrl;
        record.serverCapabilitiesSize++;
        UA_String serverCap = UA_STRING("LDS");
        record.serverCapabilities = &serverCap;

        UA_GDS_call_registerApplication(gds_client, &record, &appId);

        size_t certificateGroupSize = 0;
        UA_NodeId *certificateGroupId;
        UA_GDS_call_getCertificateGroups(gds_client, &appId, &certificateGroupSize, &certificateGroupId);

        UA_NodeId *certificateTypeId = (UA_NodeId*) UA_malloc(sizeof(UA_NodeId));
        *certificateTypeId = UA_NODEID_NUMERIC(2, 617);

        //Request a new application instance certificate (with the associated private key)
        UA_NodeId requestId;
        UA_ByteString certificaterequest;
        UA_String  subjectName  = UA_STRING("C=DE,O=open62541,CN=open62541@localhost");

        /* Does not support for new private key generation. So the value should be 0
         * To Do: Generation of private key and storing the same.
         */
        UA_Boolean regenPrivKey = false;

        UA_GDS_call_createSigningRequest(push_client, certificateGroupId, certificateTypeId, &subjectName,
                                         &regenPrivKey, &UA_BYTESTRING_NULL, &certificaterequest);


        UA_GDS_call_startSigningRequest(gds_client, &appId, certificateGroupId, certificateTypeId,
                                        &certificaterequest, &requestId);

        //Fetch the certificate and private key
        UA_ByteString certificate_gds = UA_BYTESTRING_NULL;
        UA_ByteString privateKey_gds = UA_BYTESTRING_NULL;
        UA_ByteString issuerCertificate = UA_BYTESTRING_NULL;
        UA_String privateKeyFormat = UA_STRING("DER");
        if (!UA_NodeId_isNull(&requestId)){
            do {
                retval = UA_GDS_call_finishRequest(gds_client, &appId, &requestId,
                                                               &certificate_gds, &privateKey_gds, &issuerCertificate);
            } while (retval == UA_STATUSCODE_BADNOTHINGTODO);


            /* Update Certificate */
            UA_Boolean applyChanges;
            UA_GDS_call_updateCertificates(push_client, certificateGroupId, certificateTypeId,
                                           &certificate_gds, &issuerCertificate, &privateKeyFormat, &privateKey_gds, &applyChanges);
        }

        UA_ByteString_clear(&certificate_gds);
        if (&privateKey_gds != &UA_BYTESTRING_NULL) {
            UA_ByteString_clear(&privateKey_gds);
        }

        UA_ByteString_clear(&issuerCertificate);
        UA_ByteString_clear(&certificaterequest);
        UA_free(certificateTypeId);
        UA_free(certificateGroupId);

    }

    UA_String_deleteMembers(&applicationUri);
    UA_Client_disconnect(push_client);
    UA_Client_delete(push_client);
    UA_Client_disconnect(gds_client);
    UA_Client_delete(gds_client);

    return (int)retval;
}
