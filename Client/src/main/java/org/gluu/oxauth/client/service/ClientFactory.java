/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.service;

import javax.ws.rs.core.UriBuilder;

import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient43Engine;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 26/06/2013
 */

public class ClientFactory {

    private final static ClientFactory INSTANCE = new ClientFactory();

    private ApacheHttpClient43Engine engine;

    private ClientFactory() {
        this.engine = createEngine();
    }

    public static ClientFactory instance() {
        return INSTANCE;
    }

    public IntrospectionService createIntrospectionService(String p_url) {
        return createIntrospectionService(p_url, engine);
    }
    
    public IntrospectionService createIntrospectionService(String p_url, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(p_url));
        IntrospectionService proxy = target.proxy(IntrospectionService.class);

        return proxy;
    }

    public StatService createStatService(String url) {
        return createStatService(url, engine);
    }

    public StatService createStatService(String url, ClientHttpEngine engine) {
        ResteasyClient client = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(engine).build();
        ResteasyWebTarget target = client.target(UriBuilder.fromPath(url));
        return target.proxy(StatService.class);
    }

    public ApacheHttpClient43Engine createEngine() {
        return createEngine(false);
    }

    public ApacheHttpClient43Engine createEngine(boolean followRedirects) {
        return createEngine(200, 20, CookieSpecs.STANDARD, followRedirects);
    }

	public ApacheHttpClient43Engine createEngine(int maxTotal, int defaultMaxPerRoute, String cookieSpec, boolean followRedirects) {
	    PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
	    CloseableHttpClient httpClient = HttpClients.custom()
				.setDefaultRequestConfig(RequestConfig.custom().setCookieSpec(cookieSpec).build())
	    		.setConnectionManager(cm).build();
	    cm.setMaxTotal(maxTotal);
	    cm.setDefaultMaxPerRoute(defaultMaxPerRoute);
        final ApacheHttpClient43Engine engine = new ApacheHttpClient43Engine(httpClient);
        engine.setFollowRedirects(followRedirects);
        return engine;
	}
}
