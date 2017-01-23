/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client;

import org.apache.log4j.Logger;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceRequestParam;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public class DeviceAuthorizationClient extends BaseClient<DeviceAuthorizationRequest, DeviceAuthorizationResponse> {

    private static final Logger LOG = Logger.getLogger(DeviceAuthorizationClient.class);

    public DeviceAuthorizationClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        return HttpMethod.POST;
    }

    public DeviceAuthorizationResponse exec() {
        DeviceAuthorizationResponse response = null;

        try {
            initClientRequest();
            response = exec_();
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        } finally {
            closeConnection();
        }

        return response;
    }

    private DeviceAuthorizationResponse exec_() throws Exception {
        clientRequest.header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED);
        clientRequest.setHttpMethod(getHttpMethod());

        final String scopesAsString = getRequest().getScopesAsString();

        addReqParam(AuthorizeDeviceRequestParam.RESPONSE_TYPE, getRequest().getResponseType());
        addReqParam(AuthorizeDeviceRequestParam.CLIENT_ID, getRequest().getClientId());
        addReqParam(AuthorizeDeviceRequestParam.SCOPE, scopesAsString);

        // Call REST Service and handle response
        clientResponse = clientRequest.post(String.class);

        setResponse(new DeviceAuthorizationResponse(clientResponse));

        return getResponse();
    }
}
