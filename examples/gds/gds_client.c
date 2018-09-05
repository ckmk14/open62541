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
#include "common.h"

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
                                        UA_NodeId *applicationId,
                                        size_t *cg_size,
                                        UA_NodeId **certificateGroups) {
    UA_Variant input;
    UA_Variant_setScalarCopy(&input, applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                                           UA_NODEID_NUMERIC(2, 508), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *cg_size = output->arrayLength;
        if (output->arrayLength > 0) {
            *certificateGroups = (UA_NodeId *) UA_calloc (output->arrayLength, sizeof(UA_NodeId));
            memcpy(*certificateGroups, output->data, output->arrayLength * sizeof(UA_NodeId));
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
        printf("Certificate received\n");
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    for(size_t i = 0; i < 2; i++)
        UA_Variant_deleteMembers(&input[i]);

    return retval;

}

static
UA_StatusCode call_getTrustList(UA_Client *client,
                                 UA_NodeId *applicationId,
                                 const UA_NodeId *certificateGroupId,
                                 UA_NodeId *trustListId) {

    UA_Variant input[2];
    UA_Variant_setScalarCopy(&input[0], applicationId, &UA_TYPES[UA_TYPES_NODEID]);
    UA_Variant_setScalarCopy(&input[1], certificateGroupId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                                          UA_NODEID_NUMERIC(2, 204), 2, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *trustListId =  *((UA_NodeId*)output[0].data);
        printf("TrustListId: NS:%u;Value=%u\n",
               trustListId->namespaceIndex, trustListId->identifier.numeric);
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }


    for(size_t i = 0; i < 2; i++)
        UA_Variant_deleteMembers(&input[i]);

    return retval;

}


static
UA_StatusCode call_openTrustList(UA_Client *client,
                                UA_Byte *mode,
                                UA_UInt32 *fileHandle) {

    UA_Variant input;
    UA_Variant_setScalarCopy(&input, mode, &UA_TYPES[UA_TYPES_BYTE]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 616),
                                          UA_NODEID_NUMERIC(0, 11580), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        *fileHandle = *(UA_UInt32 *) output->data;
        printf("Received FileHandle: %u\n", *fileHandle);
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    UA_Variant_deleteMembers(&input);

    return retval;

}

static
UA_StatusCode call_closeTrustList(UA_Client *client,
                                 UA_UInt32 *fileHandle) {

    UA_Variant input;
    UA_Variant_setScalarCopy(&input, fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 616),
                                          UA_NODEID_NUMERIC(0, 11583), 1, &input, NULL, NULL);
    if(retval == UA_STATUSCODE_GOOD) {
        printf("Closed TrustList\n");
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    UA_Variant_deleteMembers(&input);

    return retval;

}

/*
static
UA_StatusCode call_readTrustList(UA_Client *client,
                                 UA_UInt32 *fileHandle,
                                 UA_Int32 *length,
                                 UA_TrustListDataType *trustList) {

    UA_Variant input[2];
    UA_Variant_setScalarCopy(&input[0], fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalarCopy(&input[1], length, &UA_TYPES[UA_TYPES_INT32]);
    size_t outputSize;
    UA_Variant *output;;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 616),
                                          UA_NODEID_NUMERIC(0, 11585), 2, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_TrustListDataType *tmp =  (UA_TrustListDataType *) output->data;
        if (tmp != NULL) {
            printf("Received TrustList (TrustListSize: %lu, TrustedCRLSize: %lu)\n",
                   tmp->trustedCertificatesSize, tmp->trustedCrlsSize);
            size_t index = 0;
            trustList->trustedCertificatesSize = tmp->trustedCertificatesSize;
            trustList->trustedCertificates =
                    (UA_ByteString *) UA_malloc (sizeof(UA_ByteString) * tmp->trustedCertificatesSize);
            while (index < tmp->trustedCertificatesSize) {
                UA_ByteString_allocBuffer(&trustList->trustedCertificates[index],
                                          tmp->trustedCertificates[index].length);
                memcpy(trustList->trustedCertificates[index].data,
                       tmp->trustedCertificates[index].data,
                       tmp->trustedCertificates[index].length);
                index++;
            }
            index = 0;
            trustList->trustedCrlsSize = tmp->trustedCrlsSize;
            trustList->trustedCrls =
                    (UA_ByteString *) UA_malloc (sizeof(UA_ByteString) * tmp->trustedCrlsSize);
            while (index < tmp->trustedCrlsSize) {
                UA_ByteString_allocBuffer(&trustList->trustedCrls[index],
                                          tmp->trustedCrls[index].length);
                memcpy(trustList->trustedCrls[index].data,
                       tmp->trustedCrls[index].data,
                       tmp->trustedCrls[index].length);
                index++;
            }

            FILE *f = fopen("/home/kocybi/ca.der", "w");
            fwrite(tmp->trustedCertificates[0].data, tmp->trustedCertificates[0].length, 1, f);
            fclose(f);

         //   FILE *f2 = fopen("/home/kocybi/tl2.der", "w");
         //   fwrite(tl->trustedCertificates[1].data, tl->trustedCertificates[1].length, 1, f2);
        //    fclose(f2);


            FILE *f3 = fopen("/home/kocybi/ca.crl", "w");
            fwrite(tmp->trustedCrls[0].data, tmp->trustedCrls[0].length, 1, f3);
            fclose(f3);

            UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
        }
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }

    for(size_t i = 0; i < 2; i++)
        UA_Variant_deleteMembers(&input[i]);

    return retval;

}
 */

static
UA_StatusCode call_readTrustList_add_UAExpert(UA_Client *client,
                                 UA_UInt32 *fileHandle,
                                 UA_Int32 *length,
                                 UA_TrustListDataType *trustList) {

    UA_Variant input[2];
    UA_Variant_setScalarCopy(&input[0], fileHandle, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Variant_setScalarCopy(&input[1], length, &UA_TYPES[UA_TYPES_INT32]);
    size_t outputSize;
    UA_Variant *output;;
    UA_StatusCode retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 616),
                                          UA_NODEID_NUMERIC(0, 11585), 2, input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        UA_TrustListDataType *tmp =  (UA_TrustListDataType *) output->data;
        if (tmp != NULL) {
            printf("Received TrustList (TrustListSize: %lu, TrustedCRLSize: %lu)\n",
                   tmp->trustedCertificatesSize, tmp->trustedCrlsSize);
            size_t index = 0;
            trustList->trustedCertificatesSize = tmp->trustedCertificatesSize + 1;
            trustList->trustedCertificates =
                    (UA_ByteString *) UA_malloc (sizeof(UA_ByteString) * (tmp->trustedCertificatesSize + 1));
            while (index < tmp->trustedCertificatesSize) {
                UA_ByteString_allocBuffer(&trustList->trustedCertificates[index],
                                          tmp->trustedCertificates[index].length);
                memcpy(trustList->trustedCertificates[index].data,
                       tmp->trustedCertificates[index].data,
                       tmp->trustedCertificates[index].length);
                index++;
            }
            UA_ByteString certificate =
                    loadFile("/home/kocybi/.config/unifiedautomation/uaexpert/PKI/own/certs/uaexpert.der");
            UA_ByteString_allocBuffer(&trustList->trustedCertificates[index],
                                      certificate.length);
            memcpy(trustList->trustedCertificates[index].data, certificate.data, certificate.length);
            UA_ByteString_deleteMembers(&certificate);
            index = 0;
            trustList->trustedCrlsSize = tmp->trustedCrlsSize;
            trustList->trustedCrls =
                    (UA_ByteString *) UA_malloc (sizeof(UA_ByteString) * tmp->trustedCrlsSize);
            while (index < tmp->trustedCrlsSize) {
                UA_ByteString_allocBuffer(&trustList->trustedCrls[index],
                                          tmp->trustedCrls[index].length);
                memcpy(trustList->trustedCrls[index].data,
                       tmp->trustedCrls[index].data,
                       tmp->trustedCrls[index].length);
                index++;
            }

            FILE *f = fopen("/home/kocybi/.config/unifiedautomation/uaexpert/PKI/trusted/certs/ca.der", "w");
            fwrite(tmp->trustedCertificates[0].data, tmp->trustedCertificates[0].length, 1, f);
            fclose(f);
            FILE *f3 = fopen("/home/kocybi/.config/unifiedautomation/uaexpert/PKI/trusted/crl/ca.crl", "w");
            fwrite(tmp->trustedCrls[0].data, tmp->trustedCrls[0].length, 1, f3);
            fclose(f3);

            UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);

        }
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


    UA_String applicationUri = UA_String_fromChars("urn:open62541.example.server_register");
    UA_Client *client = UA_Client_new(UA_ClientConfig_default);
    UA_StatusCode retval = UA_Client_connect_username(client, "opc.tcp://localhost:4841", "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return (int)retval;
    }
    size_t length = 0;
    UA_ApplicationRecordDataType * records = NULL;

    //Every ApplicationURI shall be unique.
    // Therefore the client should be sure that the application is not registered yet.
    call_findApplication(client, applicationUri, &length, records);
    UA_NodeId appId = UA_NODEID_NULL;

    if (!length){
        UA_ApplicationRecordDataType record;
        UA_ApplicationRecordDataType_init(&record);
        record.applicationUri = applicationUri;
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
        call_findApplication(client, applicationUri, &length, records);

        size_t certificateGroupSize = 0;
        UA_NodeId *certificateGroupId;
        call_getCertificateGroups(client, &appId, &certificateGroupSize, &certificateGroupId);

        if (certificateGroupSize == 1) {
            printf("CertificateGroupID: NS:%u;Value=%u\n",
                   certificateGroupId->namespaceIndex, certificateGroupId->identifier.numeric);
        }

        UA_NodeId trustListId;
        UA_UInt32 filehandle;
        UA_Byte mode = 0x01; //ReadMode (Part 5,p.100).
        UA_TrustListDataType tl;
        UA_TrustListDataType_init(&tl);
        UA_Int32  tmp_length = 0;

        call_getTrustList(client, &appId, certificateGroupId, &trustListId);
        call_openTrustList(client, &mode, &filehandle);
       // call_readTrustList(client, &filehandle, &tmp_length, &tl);
        call_readTrustList_add_UAExpert(client, &filehandle, &tmp_length, &tl);
        call_closeTrustList(client, &filehandle);

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
            retval = call_finishRequest(client, &appId, &requestId, &certificate, &privateKey, &issuerCertificate);
            if (retval == UA_STATUSCODE_GOOD) {
              //  size_t trustListSize = 0;
              //  UA_STACKARRAY(UA_ByteString, trustList, trustListSize);
              //  UA_ByteString *revocationList = NULL;
              //  size_t revocationListSize = 0;
                UA_ServerConfig *config =
                        UA_ServerConfig_new_basic256sha256(4840, &certificate, &privateKey,
                                                           tl.trustedCertificates, tl.trustedCertificatesSize,
                                                           tl.trustedCrls, tl.trustedCrlsSize);
                UA_Server *server = UA_Server_new(config);
                retval = UA_Server_run(server, &running);
                UA_Server_delete(server);
                UA_ServerConfig_delete(config);

                UA_ByteString_deleteMembers(&certificate);
                UA_ByteString_deleteMembers(&privateKey);
                UA_ByteString_deleteMembers(&issuerCertificate);
                UA_free(certificateGroupId);
                UA_TrustListDataType_deleteMembers(&tl);
            }
        }
    }
    UA_String_deleteMembers(&applicationUri);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
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