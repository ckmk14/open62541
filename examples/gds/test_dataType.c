/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */


#include <signal.h>
#include "open62541.h"

static UA_StatusCode
helloWorldMethodCallback(UA_Server *server,
                         const UA_NodeId *sessionId, void *sessionHandle,
                         const UA_NodeId *methodId, void *methodContext,
                         const UA_NodeId *objectId, void *objectContext,
                         size_t inputSize, const UA_Variant *input,
                         size_t outputSize, UA_Variant *output) {
    UA_String *inputStr = (UA_String*)input->data;
    UA_String tmp = UA_STRING_ALLOC("Hello ");
    if(inputStr->length > 0) {
        tmp.data = (UA_Byte *)UA_realloc(tmp.data, tmp.length + inputStr->length);
        memcpy(&tmp.data[tmp.length], inputStr->data, inputStr->length);
        tmp.length += inputStr->length;
    }
    UA_Variant_setScalarCopy(output, &tmp, &UA_TYPES[UA_TYPES_STRING]);
    UA_String_deleteMembers(&tmp);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "Hello World was called");
    return UA_STATUSCODE_GOOD;
}


/** It follows the main server code, making use of the above definitions. */

UA_Boolean running = true;
static void stopHandler(int sign) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "received ctrl-c");
    running = false;
}

static void
addFindApplicationMethod(UA_Server *server, UA_UInt16 ns_index, UA_NodeId directoryTypeId) {
    UA_Argument inputArgument;
    UA_Argument_init(&inputArgument);
    inputArgument.description = UA_LOCALIZEDTEXT("en-US", "InputArguments");
    inputArgument.name = UA_STRING("InputArguments");
    inputArgument.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    inputArgument.valueRank = -1; /* scalar */

    UA_Argument outputArgument;
    UA_Argument_init(&outputArgument);
    outputArgument.description = UA_LOCALIZEDTEXT("en-US", "A String");
    outputArgument.name = UA_STRING("MyOutput");
    outputArgument.dataType = UA_TYPES[UA_TYPES_STRING].typeId; //hier muss applicationRecordDataType
    outputArgument.valueRank = -1; /* scalar */

    UA_NodeId methodNodeId;
    UA_MethodAttributes mAttr = UA_MethodAttributes_default;
    mAttr.displayName = UA_LOCALIZEDTEXT("en-US","FindApplication");
    mAttr.executable = true;
    mAttr.userExecutable = true;
    UA_Server_addMethodNode(server, UA_NODEID_NUMERIC(ns_index, 15),
                                               directoryTypeId,
                                               UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                               UA_QUALIFIEDNAME(ns_index, "FindApplications"),
                                               mAttr, &helloWorldMethodCallback,
                                               1, &inputArgument, 1, &outputArgument, NULL, &methodNodeId);

}


static void addDirectoryType(UA_Server *server, UA_UInt16 ns_index){
    UA_NodeId directoryTypeId= UA_NODEID_NUMERIC(ns_index, 13);
    UA_ObjectTypeAttributes dtAttr = UA_ObjectTypeAttributes_default;
    dtAttr.displayName = UA_LOCALIZEDTEXT("en-US", "DirectoryType");
    UA_Server_addObjectTypeNode(server, directoryTypeId,
                                UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                                UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE),
                                UA_QUALIFIEDNAME(ns_index, "DirectoryType"), dtAttr,
                                NULL, NULL);

    UA_NodeId applId= UA_NODEID_NUMERIC(ns_index, 14);
    UA_ObjectAttributes oAttr = UA_ObjectAttributes_default;
    oAttr.displayName = UA_LOCALIZEDTEXT("en-US", "Applications");
    UA_Server_addObjectNode(server, applId,
                            directoryTypeId,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                            UA_QUALIFIEDNAME(ns_index, "Applications"),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                            oAttr, NULL, NULL);

    addFindApplicationMethod(server,ns_index, directoryTypeId);
}

static void addGDSNamespace(UA_Server *server){
    UA_UInt16 ns_index = UA_Server_addNamespace(server, "http://opcfoundation.org/UA/GDS/");
    addDirectoryType(server, ns_index);
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    UA_ServerConfig *config = UA_ServerConfig_new_default();
    UA_Server *server = UA_Server_new(config);

    addGDSNamespace(server);

    UA_StatusCode retval = UA_Server_run(server, &running);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int)retval;
}
