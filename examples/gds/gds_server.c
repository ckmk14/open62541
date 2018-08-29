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

    UA_ByteString certificate = loadFile(argv[1]);

    UA_ServerConfig *config = UA_ServerConfig_new_minimal(4841, NULL);;



    GDS_CA *ca = config->gds_certificateGroups[0].ca;
    ca->addCertificateToTrustList(ca, &certificate, UA_TRUE);



    config->applicationDescription.applicationType = UA_APPLICATIONTYPE_DISCOVERYSERVER;
    UA_String_deleteMembers(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
            UA_String_fromChars("urn:open62541.example.global_discovery_server");
    // See http://www.opcfoundation.org/UA/schemas/1.03/ServerCapabilities.csv
    config->serverCapabilitiesSize = 1;
    UA_String *caps = UA_String_new();
    *caps = UA_String_fromChars("GDS");
    config->serverCapabilities = caps;

    UA_Server *server = UA_Server_new(config);

    UA_StatusCode retval = UA_Server_run(server, &running);

    UA_ByteString_deleteMembers(&certificate);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}
