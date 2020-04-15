/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 */

#include <open62541/server_config.h>
#ifdef UA_ENABLE_GDS_CM
#include <open62541/plugin/gds_ca_gnutls.h>
#endif

void
UA_ServerConfig_clean(UA_ServerConfig *config) {
    if(!config)
        return;

    /* Server Description */
    UA_BuildInfo_deleteMembers(&config->buildInfo);
    UA_ApplicationDescription_deleteMembers(&config->applicationDescription);
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    UA_MdnsDiscoveryConfiguration_clear(&config->discovery.mdns);
    UA_String_clear(&config->discovery.mdnsInterfaceIP);
# if !defined(UA_HAS_GETIFADDR)
    if (config->discovery.ipAddressListSize) {
        UA_free(config->discovery.ipAddressList);
    }
# endif
#endif

    /* Custom DataTypes */
    /* nothing to do */

    /* Networking */
    for(size_t i = 0; i < config->networkLayersSize; ++i)
        config->networkLayers[i].clear(&config->networkLayers[i]);
    UA_free(config->networkLayers);
    config->networkLayers = NULL;
    config->networkLayersSize = 0;
    UA_String_deleteMembers(&config->customHostname);
    config->customHostname = UA_STRING_NULL;

    for(size_t i = 0; i < config->securityPoliciesSize; ++i) {
        UA_SecurityPolicy *policy = &config->securityPolicies[i];
        policy->clear(policy);
    }
    UA_free(config->securityPolicies);
    config->securityPolicies = NULL;
    config->securityPoliciesSize = 0;

    for(size_t i = 0; i < config->endpointsSize; ++i)
        UA_EndpointDescription_deleteMembers(&config->endpoints[i]);

    UA_free(config->endpoints);
    config->endpoints = NULL;
    config->endpointsSize = 0;

    /* Nodestore */
    if(config->nodestore.context && config->nodestore.clear) {
        config->nodestore.clear(config->nodestore.context);
        config->nodestore.context = NULL;
    }

    /* Certificate Validation */
    if(config->certificateVerification.clear)
        config->certificateVerification.clear(&config->certificateVerification);

    /* Access Control */
    if(config->accessControl.clear)
        config->accessControl.clear(&config->accessControl);

    /* Historical data */
#ifdef UA_ENABLE_HISTORIZING
    if(config->historyDatabase.clear)
        config->historyDatabase.clear(&config->historyDatabase);
#endif

#ifdef UA_ENABLE_GDS_CM
    for(size_t i = 0; i < config->gds_certificateGroupSize; ++i) {
        UA_free(config->gds_certificateGroups[i].certificateTypes);
        UA_GDS_CA *ca = config->gds_certificateGroups[i].ca;
        ca->deleteMembers(ca);
        UA_free(ca);
    }
    UA_free(config->gds_certificateGroups);

    for(size_t i = 0; i < config->endpointCertificateMappingSize; i++) {
        UA_ByteString_clear(&config->endpointCertificateMapping[i].serverCertificate);
    }
    UA_free(config->endpointCertificateMapping);
    config->endpointCertificateMapping = NULL;
    config->endpointCertificateMappingSize = 0;
#endif

    /* Logger */
    if(config->logger.clear)
        config->logger.clear(config->logger.context);
}
void
UA_ServerConfig_setCustomHostname(UA_ServerConfig *config,
                                  const UA_String customHostname) {
    if(!config)
        return;
    UA_String_deleteMembers(&config->customHostname);
    UA_String_copy(&customHostname, &config->customHostname);
}

#ifdef UA_ENABLE_PUBSUB
/* Add a pubsubTransportLayer to the configuration. Memory is reallocated on
 * demand. */
UA_StatusCode
UA_ServerConfig_addPubSubTransportLayer(UA_ServerConfig *config,
        UA_PubSubTransportLayer *pubsubTransportLayer) {

    if(config->pubsubTransportLayersSize == 0) {
        config->pubsubTransportLayers = (UA_PubSubTransportLayer *)
                UA_malloc(sizeof(UA_PubSubTransportLayer));
    } else {
        config->pubsubTransportLayers = (UA_PubSubTransportLayer*)
                UA_realloc(config->pubsubTransportLayers,
                sizeof(UA_PubSubTransportLayer) * (config->pubsubTransportLayersSize + 1));
    }

    if(config->pubsubTransportLayers == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    memcpy(&config->pubsubTransportLayers[config->pubsubTransportLayersSize],
            pubsubTransportLayer, sizeof(UA_PubSubTransportLayer));
    config->pubsubTransportLayersSize++;

    return UA_STATUSCODE_GOOD;
}
#endif /* UA_ENABLE_PUBSUB */
