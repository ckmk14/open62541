/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include "open62541.h"
#include "common.h"
#include <gnutls/x509.h>
#include <open62541.h>

UA_Boolean running = true;
static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}
//
//static void save_x509(UA_ByteString crt, const char *loc) {
//    FILE *f = fopen(loc, "w");
//    fwrite(crt.data, crt.length, 1, f);
//    fclose(f);
//}

int main(int argc, char* argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    if(argc < 3) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Missing arguments. Arguments are "
                             "<server-certificate.der> <private-key.der> "
                             "[<trustlist1.crl>, ...]");
        return 1;
    }

    /* Load certificate and private key */
    UA_ByteString certificate = loadFile(argv[1]);
    UA_ByteString privateKey = loadFile(argv[2]);

    /* Load the trustlist */
    size_t trustListSize = 0;
    if(argc > 3)
        trustListSize = (size_t)argc-3;
    UA_STACKARRAY(UA_ByteString, trustList, trustListSize);
    for(size_t i = 0; i < trustListSize; i++)
        trustList[i] = loadFile(argv[i+3]);

    /* Loading of a revocation list currently unsupported */
    UA_ByteString *revocationList = NULL;
    size_t revocationListSize = 0;

    UA_ServerConfig *config =
            UA_ServerConfig_new_basic256sha256(4840, &certificate, &privateKey,
                                               trustList, trustListSize,
                                               revocationList, revocationListSize);
    UA_ByteString csr;
    memset(&csr, 0, sizeof(UA_ByteString));
    GDS_CAPlugin scg;

    UA_String name = UA_STRING("O=open62541,CN=GDS@localhost");
    UA_String name2 = UA_STRING("C=DE,O=open62541,CN=open62541@localhost");
    UA_String name3 = UA_STRING("urn:unconfigured:application");
    UA_InitCA(&scg, name, (60 * 60 * 24 * 365 * 10), 6000, 2048, config->logger);
    UA_createCSR(&scg, &csr);

    UA_ByteString cert1;
    UA_ByteString cert2;

    scg.certificateSigningRequest(&scg, &csr, 2048, &cert1);

    UA_ByteString passw;
    memset(&passw, 0, sizeof(UA_ByteString));
    scg.createNewKeyPair(&scg, name2, NULL, NULL, 2048, NULL, 0, name3, &cert2, &passw);

  //  save_x509(cert1, "/home/kocybi/app.der");
  //  save_x509(cert2, "/home/kocybi/app2.der");

    scg.deleteMembers(&scg);
    UA_ByteString_deleteMembers(&cert1);
    UA_ByteString_deleteMembers(&cert2);
    UA_ByteString_deleteMembers(&passw);
    UA_ByteString_deleteMembers(&csr);
    printf("%p", (void *) &name);
    printf("%p", (void *) &scg);
    UA_ByteString_deleteMembers(&certificate);
    UA_ByteString_deleteMembers(&privateKey);
    for(size_t i = 0; i < trustListSize; i++)
        UA_ByteString_deleteMembers(&trustList[i]);

    if(!config) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Could not create the server config");
        return 1;
    }

    UA_Server *server = UA_Server_new(config);
    UA_StatusCode retval = UA_Server_run(server, &running);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}
