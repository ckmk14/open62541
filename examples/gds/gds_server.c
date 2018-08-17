/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */


#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <open62541.h>
#include "open62541.h"
#include "common.h"
/** It follows the main server code, making use of the above definitions. */

UA_Boolean running = true;
static void stopHandler(int sign) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "received ctrl-c");
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_ServerConfig *config = UA_ServerConfig_new_minimal(4841, NULL);;

    config->applicationDescription.applicationType = UA_APPLICATIONTYPE_DISCOVERYSERVER;
    UA_String_deleteMembers(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
            UA_String_fromChars("urn:open62541.example.global_discovery_server");
//    // See http://www.opcfoundation.org/UA/schemas/1.03/ServerCapabilities.csv
    config->serverCapabilitiesSize = 1;
    UA_String *caps = UA_String_new();
    *caps = UA_String_fromChars("GDS");
    config->serverCapabilities = caps;

    ///////////////////
 //   UA_ByteString csr;
//    memset(&csr, 0, sizeof(UA_ByteString));

  //  UA_String name = UA_STRING("O=open62541,CN=GDS@localhost");
 //   UA_String name2 = UA_STRING("C=DE,O=open62541,CN=open62541@localhost");

 //   UA_String name4 = UA_STRING("192.120.0.1");
  //  UA_InitCA(&scg, name, (60 * 60 * 24 * 365 * 10), 6000, 2048, config->logger);
  //  UA_createCSR(&scg, &csr);

 //   UA_ByteString cert2;
 //   UA_ByteString passw;
 //   memset(&passw, 0, sizeof(UA_ByteString));
 //   GDS_CAPlugin *g = config->gds_certificateGroups[0].ca;
 //   g->createNewKeyPair(g, &name2, NULL, NULL, 2048, 1, &name4, NULL, &cert2, &passw);
    ///////////////////


    UA_Server *server = UA_Server_new(config);

    UA_StatusCode retval = UA_Server_run(server, &running);
   // UA_String_deleteMembers()
 //   UA_ByteString_deleteMembers(&cert2);
 //   UA_ByteString_deleteMembers(&passw);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}
