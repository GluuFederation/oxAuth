/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.uma;

import org.gluu.oxauth.client.service.ClientFactory;
import org.gluu.oxauth.model.uma.UmaMetadata;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.jboss.resteasy.specimpl.ResteasyUriBuilder;

import javax.ws.rs.core.UriBuilder;

/**
 * Helper class which creates proxied UMA services
 *
 * @author Yuriy Movchan
 * @author Yuriy Zabrovarnyy
 */
public class UmaClientFactory {

    private final static UmaClientFactory instance = new UmaClientFactory();

    private ApacheHttpClient4Engine engine;

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
        ResteasyWebTarget target = newClient(engine).target(new ResteasyUriBuilder().uri(metadata.getResourceRegistrationEndpoint()));
        return target.proxy(UmaResourceService.class);
    }

    public UmaPermissionService createPermissionService(UmaMetadata metadata) {
        return createPermissionService(metadata, engine);
    }

    public UmaPermissionService createPermissionService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyWebTarget target = newClient(engine).target(new ResteasyUriBuilder().uri(metadata.getPermissionEndpoint()));
        return target.proxy(UmaPermissionService.class);
    }

    public UmaRptIntrospectionService createRptStatusService(UmaMetadata metadata) {
        return createRptStatusService(metadata, engine);
    }

    public UmaRptIntrospectionService createRptStatusService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyWebTarget target = newClient(engine).target(new ResteasyUriBuilder().uri(metadata.getIntrospectionEndpoint()));
        return target.proxy(UmaRptIntrospectionService.class);
    }

    public UmaMetadataService createMetadataService(String umaMetadataUri) {
        return createMetadataService(umaMetadataUri, engine);
    }

    public UmaMetadataService createMetadataService(String umaMetadataUri, ClientHttpEngine engine) {
        ResteasyWebTarget target = newClient(engine).target(new ResteasyUriBuilder().uri(umaMetadataUri));
        return target.proxy(UmaMetadataService.class);
    }

    public UmaScopeService createScopeService(String scopeEndpointUri) {
        return createScopeService(scopeEndpointUri, engine);
    }

    public UmaScopeService createScopeService(String scopeEndpointUri, ClientHttpEngine engine) {
        ResteasyWebTarget target = newClient(engine).target(new ResteasyUriBuilder().uri(scopeEndpointUri));
        return target.proxy(UmaScopeService.class);
    }

    public UmaTokenService createTokenService(UmaMetadata metadata) {
        return createTokenService(metadata, engine);
    }

    public UmaTokenService createTokenService(UmaMetadata metadata, ClientHttpEngine engine) {
        ResteasyWebTarget target = newClient(engine).target(new ResteasyUriBuilder().uri(metadata.getTokenEndpoint()));
        return target.proxy(UmaTokenService.class);
    }

    public ResteasyClient newClient(ClientHttpEngine engine) {
        return new ResteasyClientBuilder().httpEngine(engine).build();
    }
}
