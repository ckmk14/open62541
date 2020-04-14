#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include "common.h"

UA_Boolean running = true;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    if(argc < 4) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Missing arguments. Arguments are "
                     "<server-certificate1.der> <private-key1.der> "
                     "<server-certificate2.der> <private-key2.der> ");
        return 1;
    }

    /* Load certificate and private key */
    UA_ByteString certificate1 = loadFile(argv[1]);
    UA_ByteString privateKey1 = loadFile(argv[2]);

    UA_ByteString certificate2 = loadFile(argv[3]);
    UA_ByteString privateKey2 = loadFile(argv[4]);

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, 4842, &certificate1);
    UA_ServerConfig_addEndpointCertificateMapping(config, &config->endpoints[0].serverCertificate, UA_NODEID_NUMERIC(2, 615), UA_NODEID_NUMERIC(2, 617));

    UA_ServerConfig_addSecurityPolicyBasic256(config, &certificate1, &privateKey1);
    UA_ByteString basic256Uri = UA_BYTESTRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256");
    UA_ServerConfig_addEndpoint(config, basic256Uri, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    UA_ServerConfig_addEndpointCertificateMapping(config, &config->endpoints[1].serverCertificate, UA_NODEID_NUMERIC(2, 615), UA_NODEID_NUMERIC(2, 617));

    UA_ServerConfig_addSecurityPolicyBasic256Sha256(config, &certificate2, &privateKey2);
    UA_ByteString basic256Sha256Uri = UA_BYTESTRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    UA_ServerConfig_addEndpoint(config, basic256Sha256Uri, UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    UA_ServerConfig_addEndpointCertificateMapping(config, &config->endpoints[2].serverCertificate, UA_NODEID_NUMERIC(1, 615), UA_NODEID_NUMERIC(1, 616));

    UA_ByteString_clear(&certificate1);
    UA_ByteString_clear(&privateKey1);
    UA_ByteString_clear(&certificate2);
    UA_ByteString_clear(&privateKey2);

    if(!config) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Could not create the server config");
        return 1;
    }


    UA_Server_run(server, &running);
    UA_Server_delete(server);
    return 0;
}
