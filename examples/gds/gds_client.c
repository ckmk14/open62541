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
            printf("URI already registered\n");
            *length = 1;
            //TODO copy records (unnecessary for now)
            UA_ApplicationRecordDataType *record3 = (UA_ApplicationRecordDataType *) eo->content.decoded.data;
            printf("%u", record3->applicationId.namespaceIndex);
        }
        else {
            printf("URI is not assigned yet\n");
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
        printf("Method call was successful, and %lu returned values available.\n",
               (unsigned long)outputSize);

        *newNodeId =  *((UA_NodeId*)output[0].data);
        printf("%u\n", newNodeId->namespaceIndex);
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);
    return retval;
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
        printf("4Method call was successful, and %lu returned values available.\n",
               (unsigned long)outputSize);

        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);
    return retval;
}
*/
static UA_StatusCode call_getCertificateGroups(UA_Client *client,
                                               UA_NodeId *newNodeId) {
    UA_Variant input;
    UA_Variant_setScalarCopy(&input, newNodeId, &UA_TYPES[UA_TYPES_NODEID]);
    size_t outputSize;
    UA_Variant *output;
    UA_StatusCode  retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                                           UA_NODEID_NUMERIC(2, 508), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        printf("4Method call was successful, and %lu returned values available.\n",
               (unsigned long)outputSize);

        UA_NodeId *certificateGroups = (UA_NodeId*) output->data;
        if (certificateGroups != NULL) {
      //      UA_ApplicationRecordDataType *record3 = (UA_ApplicationRecordDataType *) eo->content.decoded.data;
      //      printf("%u", record3->applicationId.namespaceIndex);
        }

        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);
    return retval;
}


int main(int argc, char **argv) {
    signal(SIGINT, stopHandler); /* catches ctrl-c */
    signal(SIGTERM, stopHandler);

    UA_ServerConfig *config = UA_ServerConfig_new_default();
    UA_String_deleteMembers(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_String_fromChars("urn:open62541.example.server_register");

    UA_Server *server = UA_Server_new(config);
    UA_Client *client = UA_Client_new(UA_ClientConfig_default);
    UA_StatusCode retval = UA_Client_connect_username(client, "opc.tcp://localhost:4841", "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return (int)retval;
    }

    size_t length = 0;
    UA_ApplicationRecordDataType * records = NULL;
    call_findApplication(client, config->applicationDescription.applicationUri, &length, records);
    UA_NodeId nodeId = UA_NODEID_NULL;
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

        call_registerApplication(client, &record, &nodeId);
    }
    call_getCertificateGroups(client, &nodeId);

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


    UA_Client_disconnect(client);
    UA_Client_delete(client);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}
