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

    UA_Client*              client             = NULL;
    UA_Client*              client_push        = NULL;
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

    /* Secure client initialization */
    client= UA_Client_new();
    UA_ClientConfig *config = UA_Client_getConfig(client);
    config->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_ClientConfig_setDefaultEncryption(config, certificate, privateKey, trustList, trustListSize, revocationList, revocationListSize);

    if(client == NULL) {
        return FAILURE;
    }

    UA_String applicationUri = UA_String_fromChars("urn:open62541.server.application");

    /* Change the localhost to the IP running GDS if needed */
    retval = UA_Client_connect_username(client, CONNECTION_STRING1, "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        UA_String_deleteMembers(&applicationUri);
        return (int)retval;
    }

    /* Secure client initialization */
    client_push = UA_Client_new();
    UA_ClientConfig *config_push = UA_Client_getConfig(client_push);
    config_push->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    UA_ClientConfig_setDefaultEncryption(config_push, certificate, privateKey, trustList, trustListSize, revocationList, revocationListSize);


    if(client_push == NULL) {
        return FAILURE;
    }

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for(size_t deleteCount = 0; deleteCount < trustListSize; deleteCount++) {
        UA_ByteString_clear(&trustList[deleteCount]);
    }

    /* A client to connect to the OPC UA server for pushing the certificate */
    retval = UA_Client_connect_username(client_push, CONNECTION_STRING2, "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client_push);
        return (int)retval;
    }

    /* Every ApplicationURI shall be unique.
     * Therefore the client should be sure that the application is not registered yet. */
    size_t length = 0;
    UA_ApplicationRecordDataType *records = NULL;
    UA_GDS_call_findApplication(client, applicationUri, &length, records);

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

        UA_GDS_call_registerApplication(client, &record, &appId);

        //Request a new application instance certificate (with the associated private key)
        UA_NodeId requestId;
        UA_ByteString certificaterequest;
        UA_String  subjectName  = UA_STRING("C=DE,O=open62541,CN=open62541@localhost");

        /* Does not support for new private key generation. So the value should be 0
         * To Do: Generation of private key and storing the same.
         */
        UA_Boolean regenPrivKey = 0;

        UA_GDS_call_createSigningRequest(client_push, &UA_NODEID_NULL, &UA_NODEID_NULL, &subjectName,
                                         &regenPrivKey, &UA_BYTESTRING_NULL, &certificaterequest);

        UA_GDS_call_startSigningRequest(client, &appId, &UA_NODEID_NULL, &UA_NODEID_NULL,
                                        &certificaterequest, &requestId);

        //Fetch the certificate and private key
        UA_ByteString certificate_gds;
        UA_ByteString privateKey_gds;
        UA_ByteString issuerCertificate;
        UA_String privateKeyFormat = UA_STRING("DER");
        if (!UA_NodeId_isNull(&requestId)){
            do {
                retval = UA_GDS_call_finishRequest(client, &appId, &requestId,
                                                               &certificate_gds, &privateKey_gds, &issuerCertificate);
            } while (retval == UA_STATUSCODE_BADNOTHINGTODO);


            /* Update Certificate */
            UA_Boolean applyChanges;
            UA_GDS_call_updateCertificates(client_push, &UA_NODEID_NULL, &UA_NODEID_NULL,
                                           &certificate_gds, &issuerCertificate, &privateKeyFormat, &privateKey_gds, &applyChanges);
        }

        UA_ByteString_clear(&certificate_gds);
        if (&privateKey_gds != &UA_BYTESTRING_NULL) {
            UA_ByteString_clear(&privateKey_gds);
        }

        UA_ByteString_clear(&issuerCertificate);
        UA_ByteString_clear(&certificaterequest);

    }

    UA_String_deleteMembers(&applicationUri);
    UA_Client_disconnect(client_push);
    UA_Client_delete(client_push);
    UA_Client_disconnect(client);
    UA_Client_delete(client);

    return (int)retval;
}
