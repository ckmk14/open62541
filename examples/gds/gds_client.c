/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */
/*
 * A simple server instance which registers with the discovery server (see server_lds.c).
 * Before shutdown it has to unregister itself.
 */


#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <open62541.h>
#include "open62541.h"

UA_Logger logger = UA_Log_Stdout;
UA_Boolean running = true;

static void stopHandler(int sign) {
    UA_LOG_INFO(logger, UA_LOGCATEGORY_SERVER, "received ctrl-c");
    running = false;
}

/*
static UA_StatusCode call_unregisterApplication(UA_Client *client,
                                                UA_NodeId *newNodeId) {
    UA_Variant input;
    UA_Variant_setScalarCopy(&input, newNodeId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                                      UA_NODEID_NUMERIC(2, 149), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);
    return retval;
}

static
UA_StatusCode call_startSigningRequest(UA_Client *client,
                                          UA_NodeId *applicationId,
                                          const UA_NodeId *certificateGroupId,
                                          const UA_NodeId *certificateTypeId,
                                          UA_ByteString *csr,
                                          UA_NodeId *requestId) {
    UA_Variant input[4];

    UA_Variant_setScalarCopy(&input[0], applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[1], certificateGroupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[2], certificateTypeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[3], csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 157), 4, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *requestId =  *((UA_NodeId*)output[0].data);
        printf("RequestID: " UA_PRINTF_GUID_FORMAT "\n",
               UA_PRINTF_GUID_DATA(requestId->identifier.guid));
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    for(size_t i = 0; i < 4; i++)
        UA_Variant_deleteMembers(&input[i]);;

    return retval;
}
*/

static UA_StatusCode call_findApplication(UA_Client *client,
                                          UA_String uri,
                                          size_t *length,
                                          UA_ApplicationRecordDataType *records) {
    UA_Variant input;
    UA_Variant_setScalarCopy(&input, &uri, &UA_TYPES[UA_TYPES_STRING]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 143), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_ExtensionObject *eo = (UA_ExtensionObject*) output->data;
        if (eo != NULL) {
            *length = output->arrayLength;
            //TODO copy records (unnecessary for now)
       //     UA_ApplicationRecordDataType *record3 = (UA_ApplicationRecordDataType *) eo->content.decoded.data;
        }
        else {
            *length = 0;
        }
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);
    return retval;
}

static UA_StatusCode call_registerApplication(UA_Client *client,
                                          UA_ApplicationRecordDataType *record,
                                          UA_NodeId *newNodeId) {

    UA_Variant input;
    UA_Variant_setScalarCopy(&input, record, &UA_TYPES[UA_TYPES_APPLICATIONRECORDDATATYPE]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 146), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *newNodeId =  *((UA_NodeId*)output[0].data);
        printf("ApplicationID: " UA_PRINTF_GUID_FORMAT "\n",
               UA_PRINTF_GUID_DATA(newNodeId->identifier.guid));
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    UA_Variant_deleteMembers(&input);
    return retval;
}

/*
static
UA_StatusCode call_startSigningRequest(UA_Client *client,
                                          UA_NodeId *applicationId,
                                          const UA_NodeId *certificateGroupId,
                                          const UA_NodeId *certificateTypeId,
                                          UA_ByteString *csr,
                                          UA_NodeId *requestId) {
    UA_Variant input[4];

    UA_Variant_setScalarCopy(&input[0], applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[1], certificateGroupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[2], certificateTypeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[3], csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 157), 4, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *requestId =  *((UA_NodeId*)output[0].data);
        printf("RequestID: " UA_PRINTF_GUID_FORMAT "\n",
               UA_PRINTF_GUID_DATA(requestId->identifier.guid));
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    for(size_t i = 0; i < 4; i++)
        UA_Variant_deleteMembers(&input[i]);;

    return retval;
}
*/

static
UA_StatusCode call_getCertificateGroups(UA_Client *client,
                                               UA_NodeId *applicationId) {
    UA_Variant input;
    UA_Variant_setScalarCopy(&input, applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                                           UA_NODEID_NUMERIC(2, 508), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_NodeId *certificateGroups = (UA_NodeId*) output->data;
        if (certificateGroups != NULL) {
            printf("CertificateGroupID: NS:%u;Value=%u\n",
                   certificateGroups->namespaceIndex, certificateGroups->identifier.numeric);
        }

        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);
    return retval;
}

static
UA_StatusCode call_startNewKeyPairRequest(UA_Client *client,
                                                 UA_NodeId *applicationId,
                                                 const UA_NodeId *certificateGroupId,
                                                 const UA_NodeId *certificateTypeId,
                                                 UA_String *subjectName,
                                                 size_t domainNameLength,
                                                 UA_String *domainNames,
                                                 const UA_String *privateKeyFormat,
                                                 const UA_String *privateKeyPassword,
                                                 UA_NodeId *requestId) {
    UA_Variant input[7];

    UA_Variant_setScalarCopy(&input[0], applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[1], certificateGroupId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[2], certificateTypeId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[3], subjectName, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setArrayCopy(&input[4], domainNames, 3, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalarCopy(&input[5], privateKeyFormat, &UA_TYPES[UA_TYPES_STRING]);
    UA_Variant_setScalarCopy(&input[6], privateKeyPassword, &UA_TYPES[UA_TYPES_STRING]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 154), 7, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *requestId =  *((UA_NodeId*)output[0].data);
        printf("RequestID: " UA_PRINTF_GUID_FORMAT "\n",
               UA_PRINTF_GUID_DATA(requestId->identifier.guid));
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    for(size_t i = 0; i < 7; i++)
        UA_Variant_deleteMembers(&input[i]);;

    return retval;
}

static
UA_StatusCode call_finishRequest(UA_Client *client,
                                 UA_NodeId *applicationId,
                                 UA_NodeId *requestId,
                                 UA_ByteString *certificate,
                                 UA_ByteString *privateKey,
                                 UA_ByteString *issuerCertificate) {

    UA_Variant input[2];
    UA_Variant_setScalarCopy(&input[0], applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[1], requestId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 163), 2, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_ByteString *cert = (UA_ByteString *) output[0].data;
        UA_ByteString_allocBuffer(certificate, cert->length);
        memcpy(certificate->data, cert->data, cert->length);

        UA_ByteString *privKey = (UA_ByteString *) output[1].data;
        if (privKey != NULL) {
            UA_ByteString_allocBuffer(privateKey, privKey->length);
            memcpy(privateKey->data, privKey->data, privKey->length);
        }

        UA_ByteString *issuer = (UA_ByteString *) output[2].data;
        UA_ByteString_allocBuffer(issuerCertificate, issuer->length);
        memcpy(issuerCertificate[0].data, issuer[0].data, issuer->length);

        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    for(size_t i = 0; i < 2; i++)
        UA_Variant_deleteMembers(&input[i]);

    return retval;

}


int main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_ServerConfig *config = UA_ServerConfig_new_default();
    UA_String_deleteMembers(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_String_fromChars("urn:open62541.example.server_register");

    UA_Server *server = UA_Server_new(config);
    UA_Client *client = UA_Client_new(UA_ClientConfig_default);
    UA_StatusCode retval = UA_Client_connect_username(client, "opc.tcp://localhost:4841", "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        UA_Server_delete(server);
        UA_ServerConfig_delete(config);
        return (int)retval;
    }
    size_t length = 0;
    UA_ApplicationRecordDataType * records = NULL;

    //Every ApplicationURI shall be unique.
    // Therefore the client should be sure that the application is not registered yet.
    call_findApplication(client, config->applicationDescription.applicationUri, &length, records);
    UA_NodeId appId = UA_NODEID_NULL;

    if (!length){
        UA_ApplicationRecordDataType record;
        UA_ApplicationRecordDataType_init(&record);
        record.applicationUri = config->applicationDescription.applicationUri;
        record.applicationType = UA_APPLICATIONTYPE_SERVER;
        record.productUri = UA_STRING("urn:open62541.example.server_register");
        record.applicationNamesSize++;
        UA_LocalizedText applicationName = UA_LOCALIZEDTEXT("en-US", "open62541_Server");
        record.applicationNames = &applicationName;
        record.discoveryUrlsSize++;
        UA_String discoveryUrl = UA_STRING("opc.tcp://localhost:4840");
        record.discoveryUrls = &discoveryUrl;
        record.serverCapabilitiesSize++;
        UA_String serverCap = UA_STRING("LDS");
        record.serverCapabilities = &serverCap;

        call_registerApplication(client, &record, &appId);


        call_findApplication(client, config->applicationDescription.applicationUri, &length, records);

        call_getCertificateGroups(client, &appId);

        UA_NodeId requestId;

        UA_String subjectName = UA_STRING("C=DE,O=open62541,CN=open62541@localhost");
        UA_String appURI = UA_STRING("urn:unconfigured:application");
        UA_String ipAddress = UA_STRING("192.168.0.1");
        UA_String dnsName = UA_STRING("ILT532-ubuntu");
        UA_String domainNames[3] = {appURI, ipAddress, dnsName};


        call_startNewKeyPairRequest(client, &appId, &UA_NODEID_NULL, &UA_NODEID_NULL,
                                    &subjectName, 3, domainNames,
                                    &UA_STRING_NULL,&UA_STRING_NULL, &requestId);

        UA_ByteString certificate;
        UA_ByteString privateKey;
        UA_ByteString issuerCertificate;

        if (!UA_NodeId_isNull(&requestId)){
            call_finishRequest(client, &appId, &requestId, &certificate, &privateKey, &issuerCertificate);

            FILE *f = fopen("/home/kocybi/aaa.der", "w");
            fwrite(certificate.data, certificate.length, 1, f);
            fclose(f);

            FILE *f2 = fopen("/home/kocybi/aaa2.der", "w");
            fwrite(privateKey.data, privateKey.length, 1, f2);
            fclose(f2);

            FILE *f3 = fopen("/home/kocybi/aaa3.der", "w");
            fwrite(issuerCertificate.data, issuerCertificate.length, 1, f3);
            fclose(f3);

            UA_ByteString_deleteMembers(&certificate);
            UA_ByteString_deleteMembers(&privateKey);
            UA_ByteString_deleteMembers(&issuerCertificate);
        }

    }

    UA_Client_disconnect(client);
    UA_Client_delete(client);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}



//
//    char *paths[3] = {"Directory", "CertificateGroups", "DefaultApplicationGroup"};
//    UA_UInt32 ids[3] = {UA_NS0ID_ORGANIZES, UA_NS0ID_ORGANIZES, UA_NS0ID_HASCOMPONENT};
//    UA_BrowsePath browsePath;
//    UA_BrowsePath_init(&browsePath);
//    browsePath.startingNode = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
//    browsePath.relativePath.elements = (UA_RelativePathElement*)UA_Array_new(3, &UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
//    browsePath.relativePath.elementsSize = 3;
//
//
//        UA_RelativePathElement *elem = &browsePath.relativePath.elements[0];
//        elem->referenceTypeId = UA_NODEID_NUMERIC(0, ids[0]);
//        elem->targetName = UA_QUALIFIEDNAME_ALLOC(2, paths[0]);
//
//        elem = &browsePath.relativePath.elements[1];
//        elem->referenceTypeId = UA_NODEID_NUMERIC(0, ids[1]);
//        elem->targetName = UA_QUALIFIEDNAME_ALLOC(2, paths[1]);
//
//        elem = &browsePath.relativePath.elements[2];
//        elem->referenceTypeId = UA_NODEID_NUMERIC(0, ids[2]);
//        elem->targetName = UA_QUALIFIEDNAME_ALLOC(0, paths[2]);
//
//
//    UA_TranslateBrowsePathsToNodeIdsRequest request;
//    UA_TranslateBrowsePathsToNodeIdsRequest_init(&request);
//    request.browsePaths = &browsePath;
//    request.browsePathsSize = 1;
//
//    UA_TranslateBrowsePathsToNodeIdsResponse response = UA_Client_Service_translateBrowsePathsToNodeIds(client, request);
//    printf("%u",response.results[0].targets[0].targetId.nodeId.namespaceIndex);

// size_t length2 = 0;
// UA_ApplicationRecordDataType * records2 = NULL;
//  call_findApplication(client, config->applicationDescription.applicationUri, &length2, records2);
//    call_unregisterApplication(client, &nodeId);