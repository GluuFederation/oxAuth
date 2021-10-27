/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.uma;

import javax.ws.rs.core.UriBuilder;

import org.gluu.oxauth.client.service.ClientFactory;
import org.gluu.oxauth.model.uma.UmaMetadata;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient43Engine;

/**
 * Helper class which creates proxied UMA services
 *
 * @author Yuriy Movchan
 * @author Yuriy Zabrovarnyy
 */
public class UmaClientFactory {

    private final static UmaClientFactory instance = new UmaClientFactory();

    private ApacheHttpClient43Engine engine;

    private UmaClientFactory() {
        this.engine = ClientFactory.instance().createEngine(true);
    }

    public static UmaClientFactory instance() {
        return instance;
    }

    public UmaResourceService createResourceService(UmaMetadata metadata) {
        return createResourceService(metadata, engine);
    }

    public UmaResourceService createResourceService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(metadata.getResourceRegistrationEndpoint()));
        UmaResourceService proxy = target.proxy(UmaResourceService.class);

        return proxy;
    }

    public UmaPermissionService createPermissionService(UmaMetadata metadata) {
        return createPermissionService(metadata, engine);
    }

    public UmaPermissionService createPermissionService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(metadata.getPermissionEndpoint()));
        UmaPermissionService proxy = target.proxy(UmaPermissionService.class);

        return proxy;
    }

    public UmaRptIntrospectionService createRptStatusService(UmaMetadata metadata) {
        return createRptStatusService(metadata, engine);
    }

    public UmaRptIntrospectionService createRptStatusService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(metadata.getIntrospectionEndpoint()));
        UmaRptIntrospectionService proxy = target.proxy(UmaRptIntrospectionService.class);

        return proxy;
    }

    public UmaMetadataService createMetadataService(String umaMetadataUri) {
        return createMetadataService(umaMetadataUri, engine);
    }

    public UmaMetadataService createMetadataService(String umaMetadataUri, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(umaMetadataUri));
        UmaMetadataService proxy = target.proxy(UmaMetadataService.class);

        return proxy;
    }

    public UmaScopeService createScopeService(String scopeEndpointUri) {
        return createScopeService(scopeEndpointUri, engine);
    }

    public UmaScopeService createScopeService(String scopeEndpointUri, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(scopeEndpointUri));
        UmaScopeService proxy = target.proxy(UmaScopeService.class);

        return proxy;
    }

    public UmaTokenService createTokenService(UmaMetadata metadata) {
        return createTokenService(metadata, engine);
    }

    public UmaTokenService createTokenService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(metadata.getTokenEndpoint()));
        UmaTokenService proxy = target.proxy(UmaTokenService.class);

        return proxy;
    }

    public ResteasyClient newClient(ClientHttpEngine engine) {
        return ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
    }
}
