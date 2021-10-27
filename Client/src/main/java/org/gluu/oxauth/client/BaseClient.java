/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client;

import static org.gluu.oxauth.client.AuthorizationRequest.NO_REDIRECT_HEADER;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.gluu.oxauth.model.common.AuthenticationMethod;
import org.gluu.oxauth.model.common.AuthorizationMethod;
import org.gluu.oxauth.model.common.HasParamName;
import org.gluu.oxauth.model.util.Util;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;

/**
 * Allows to retrieve HTTP requests to the authorization server and responses from it for display purposes.
 *
 * @author Javier Rojas Blum
 * @version May 28, 2020
 */
public abstract class BaseClient<T extends BaseRequest, V extends BaseResponse> {

    private static final Logger LOG = Logger.getLogger(BaseClient.class);

    private String url;

    protected T request;
    protected V response;
    protected ResteasyClient resteasyClient = null;
    protected WebTarget webTarget = null;
    protected Form requestForm = new Form();
    protected Response clientResponse = null;
    private final List<Cookie> cookies = new ArrayList<Cookie>();
    private final Map<String, String> headers = new HashMap<String, String>();

    protected ClientHttpEngine executor = null;

    public BaseClient() {
    }

    public BaseClient(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public T getRequest() {
        return request;
    }

    public void setRequest(T request) {
        this.request = request;
    }

    public V getResponse() {
        return response;
    }

    public void setResponse(V response) {
        this.response = response;
    }

    public ClientHttpEngine getExecutor() {
        return executor;
    }

    public void setExecutor(ClientHttpEngine executor) {
        this.executor = executor;
    }

    protected void addReqParam(String p_key, HasParamName p_value) {
        if (p_value != null) {
            addReqParam(p_key, p_value.getParamName());
        }
    }

    protected void addReqParam(String p_key, String p_value) {
        if (Util.allNotBlank(p_key, p_value)) {
            if (request.getAuthorizationMethod() == AuthorizationMethod.FORM_ENCODED_BODY_PARAMETER) {
            	requestForm.param(p_key, p_value);
            } else {
            	webTarget = webTarget.queryParam(p_key, p_value);
            }
        }
    }
/*
    public static void putAllFormParameters(ClientRequest p_clientRequest, BaseRequest p_request) {
        if (p_clientRequest != null && p_request != null) {
            final Map<String, String> parameters = p_request.getParameters();
            if (parameters != null && !parameters.isEmpty()) {
                for (Map.Entry<String, String> e : parameters.entrySet()) {
                    p_requestForm.param(e.getKey(), e.getValue());
                }
            }
        }
    }
*/
    public String getRequestAsString() {
        StringBuilder sb = new StringBuilder();

        try {
            URL theUrl = new URL(url);

            if (getHttpMethod().equals(HttpMethod.POST) || getHttpMethod().equals(HttpMethod.PUT) || getHttpMethod().equals(HttpMethod.DELETE)) {
                sb.append(getHttpMethod()).append(" ").append(theUrl.getPath()).append(" HTTP/1.1");
                if (StringUtils.isNotBlank(request.getContentType())) {
                    sb.append("\n");
                    sb.append("Content-Type: ").append(request.getContentType());
                }
                if (StringUtils.isNotBlank(request.getMediaType())) {
                    sb.append("\n");
                    sb.append("Accept: ").append(request.getMediaType());
                }
                sb.append("\n");
                sb.append("Host: ").append(theUrl.getHost());

                if (request instanceof AuthorizationRequest) {
                    AuthorizationRequest authorizationRequest = (AuthorizationRequest) request;
                    if (authorizationRequest.isUseNoRedirectHeader()) {
                        sb.append("\n");
                        sb.append(NO_REDIRECT_HEADER + ": true");
                    }
                }
                if (request.getAuthorizationMethod() == null) {
                    if (request.getAuthenticationMethod() == null
                            || request.getAuthenticationMethod() == AuthenticationMethod.CLIENT_SECRET_BASIC) {
                        if (request.hasCredentials()) {
                            String encodedCredentials = request.getEncodedCredentials();
                            sb.append("\n");
                            sb.append("Authorization: Basic ").append(encodedCredentials);
                        }
                    }
                } else if (request.getAuthorizationMethod() == AuthorizationMethod.AUTHORIZATION_REQUEST_HEADER_FIELD) {
                    if (request instanceof UserInfoRequest) {
                        String accessToken = ((UserInfoRequest) request).getAccessToken();
                        sb.append("\n");
                        sb.append("Authorization: Bearer ").append(accessToken);
                    }
                }

                sb.append("\n");
                sb.append("\n");
                sb.append(request.getQueryString());
            } else if (getHttpMethod().equals(HttpMethod.GET)) {
                sb.append(getHttpMethod()).append(" ").append(theUrl.getPath()).append(" HTTP/1.1");
                if (StringUtils.isNotBlank(request.getQueryString())) {
                    sb.append("?").append(request.getQueryString());
                }
                sb.append(" HTTP/1.1");
                sb.append("\n");
                sb.append("Host: ").append(theUrl.getHost());

                if (request instanceof AuthorizationRequest) {
                    AuthorizationRequest authorizationRequest = (AuthorizationRequest) request;
                    if (authorizationRequest.isUseNoRedirectHeader()) {
                        sb.append("\n");
                        sb.append(NO_REDIRECT_HEADER + ": true");
                    }
                }
                if (request.getAuthorizationMethod() == null) {
                    if (request.hasCredentials()) {
                        String encodedCredentials = request.getEncodedCredentials();
                        sb.append("\n");
                        sb.append("Authorization: Basic ").append(encodedCredentials);
                    } else if (request instanceof RegisterRequest) {
                        RegisterRequest r = (RegisterRequest) request;
                        String registrationAccessToken = r.getRegistrationAccessToken();
                        sb.append("\n");
                        sb.append("Authorization: Bearer ").append(registrationAccessToken);
                    }
                } else if (request.getAuthorizationMethod() == AuthorizationMethod.AUTHORIZATION_REQUEST_HEADER_FIELD) {
                    if (request instanceof UserInfoRequest) {
                        String accessToken = ((UserInfoRequest) request).getAccessToken();
                        sb.append("\n");
                        sb.append("Authorization: Bearer ").append(accessToken);
                    }
                }
            }
        } catch (MalformedURLException e) {
            LOG.error(e.getMessage(), e);
        }

        return sb.toString();
    }

    public String getResponseAsString() {
        StringBuilder sb = new StringBuilder();

        if (response != null) {
            sb.append("HTTP/1.1 ").append(response.getStatus());
            if (response.getHeaders() != null) {
                for (String key : response.getHeaders().keySet()) {
                    sb.append("\n")
                            .append(key)
                            .append(": ")
                            .append(response.getHeaders().get(key).get(0));
                }
            }
            if (response.getEntity() != null) {
                sb.append("\n");
                sb.append("\n");
                sb.append(response.getEntity());
            }
        }
        return sb.toString();
    }

    protected void initClientRequest() {
        if (this.executor == null) {
        	resteasyClient = (ResteasyClient) ResteasyClientBuilder.newClient();
        } else {
        	resteasyClient = ((ResteasyClientBuilder) ResteasyClientBuilder.newBuilder()).httpEngine(executor).build();
        }

        webTarget = resteasyClient.target(getUrl());
    }

    protected void applyCookies(Builder clientRequest) {
		for (Cookie cookie : cookies) {
            clientRequest.cookie(cookie);
        }
        for (Map.Entry<String, String> headerEntry : headers.entrySet()) {
            clientRequest.header(headerEntry.getKey(), headerEntry.getValue());
        }
    }

    public void closeConnection() {
        try {
            if (clientResponse != null) {
                clientResponse.close();
            }
            // Why we should close engine after processing response?
//            if (resteasyClient != null && resteasyClient.httpEngine() != null) {
//            	resteasyClient.httpEngine().close();
//            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    public abstract String getHttpMethod();

    public List<Cookie> getCookies() {
        return cookies;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

}