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


int main(int argc, char **argv) {
    signal(SIGINT, stopHandler); /* catches ctrl-c */
    signal(SIGTERM, stopHandler);

    UA_ServerConfig *config = UA_ServerConfig_new_default();
    UA_String_deleteMembers(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri = UA_String_fromChars("urn:open62541.example.server_register");

    //has to be put in config
    UA_InitGDSRegistrationManager(&config->gds_rm);

    UA_Server *server = UA_Server_new(config);


    UA_Client *client = UA_Client_new(UA_ClientConfig_default);
    UA_StatusCode retval = UA_Client_connect_username(client, "opc.tcp://localhost:4841", "user1", "password");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_delete(client);
        return (int)retval;
    }

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




    UA_Variant input;
    UA_Variant_setScalarCopy(&input, &record, &UA_TYPES[UA_TYPES_APPLICATIONRECORDDATATYPE]);
    size_t outputSize;
    UA_Variant *output;
    retval = UA_Client_call(client, UA_NODEID_NUMERIC(2, 141),
                            UA_NODEID_NUMERIC(2, 146), 1, &input, &outputSize, &output);
    if(retval == UA_STATUSCODE_GOOD) {
        printf("Method call was successful, and %lu returned values available.\n",
               (unsigned long)outputSize);

        UA_NodeId *test =  (UA_NodeId*) output[0].data;
        printf("%u\n", test->namespaceIndex);
        UA_Array_delete(output, outputSize, &UA_TYPES[UA_TYPES_VARIANT]);
    } else {
        printf("Method call was unsuccessful, and %x returned values available.\n", retval);
    }
    UA_Variant_deleteMembers(&input);

  //  UA_String_deleteMembers(&record.productUri);
   // UA_LocalizedText_deleteMembers(&record.applicationNames[0]);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}
