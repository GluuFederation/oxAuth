/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client;

import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.ACR_VALUES;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.BINDING_MESSAGE;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.CLIENT_ID;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.CLIENT_NOTIFICATION_TOKEN;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.ID_TOKEN_HINT;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.LOGIN_HINT;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.LOGIN_HINT_TOKEN;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.REQUEST;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.REQUESTED_EXPIRY;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.REQUEST_URI;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.SCOPE;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationRequestParam.USER_CODE;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationResponseParam.AUTH_REQ_ID;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationResponseParam.EXPIRES_IN;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationResponseParam.INTERVAL;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.gluu.oxauth.model.common.AuthenticationMethod;
import org.gluu.oxauth.model.util.Util;
import org.json.JSONObject;

/**
 * Encapsulates functionality to make backchannel authentication request calls to an authorization server via REST Services.
 *
 * @author Javier Rojas Blum
 * @version September 4, 2019
 */
public class BackchannelAuthenticationClient extends BaseClient<BackchannelAuthenticationRequest, BackchannelAuthenticationResponse> {

    private static final Logger LOG = Logger.getLogger(BackchannelAuthenticationClient.class);

    /**
     * Constructs a backchannel authentication client by providing a REST url where the
     * backchannel authentication service is located.
     *
     * @param url The REST Service location.
     */
    public BackchannelAuthenticationClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        return HttpMethod.POST;
    }

    /**
     * Executes the call to the REST Service and processes the response.
     *
     * @return The authorization response.
     */
    public BackchannelAuthenticationResponse exec() {
        BackchannelAuthenticationResponse response = null;

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

    private BackchannelAuthenticationResponse exec_() throws Exception {
        final String scopesAsString = Util.listAsString(getRequest().getScope());
        final String acrValuesAsString = Util.listAsString(getRequest().getAcrValues());

        if (StringUtils.isNotBlank(scopesAsString)) {
        	requestForm.param(SCOPE, scopesAsString);
        }
        if (StringUtils.isNotBlank(getRequest().getClientNotificationToken())) {
            requestForm.param(CLIENT_NOTIFICATION_TOKEN, getRequest().getClientNotificationToken());
        }
        if (StringUtils.isNotBlank(acrValuesAsString)) {
            requestForm.param(ACR_VALUES, acrValuesAsString);
        }
        if (StringUtils.isNotBlank(getRequest().getLoginHintToken())) {
            requestForm.param(LOGIN_HINT_TOKEN, getRequest().getLoginHintToken());
        }
        if (StringUtils.isNotBlank(getRequest().getIdTokenHint())) {
            requestForm.param(ID_TOKEN_HINT, getRequest().getIdTokenHint());
        }
        if (StringUtils.isNotBlank(getRequest().getLoginHint())) {
            requestForm.param(LOGIN_HINT, getRequest().getLoginHint());
        }
        if (StringUtils.isNotBlank(getRequest().getBindingMessage())) {
            requestForm.param(BINDING_MESSAGE, getRequest().getBindingMessage());
        }
        if (StringUtils.isNotBlank(getRequest().getUserCode())) {
            requestForm.param(USER_CODE, getRequest().getUserCode());
        }
        if (getRequest().getRequestedExpiry() != null) {
            requestForm.param(REQUESTED_EXPIRY, getRequest().getRequestedExpiry().toString());
        }
        if (StringUtils.isNotBlank(getRequest().getClientId())) {
            requestForm.param(CLIENT_ID, getRequest().getClientId());
        }
        if (StringUtils.isNotBlank(getRequest().getRequest())) {
            requestForm.param(REQUEST, getRequest().getRequest());
        }
        if (StringUtils.isNotBlank(getRequest().getRequestUri())) {
            requestForm.param(REQUEST_URI, getRequest().getRequestUri());
        }

        Builder clientRequest = webTarget.request();
        applyCookies(clientRequest);

        // Prepare request parameters
////    clientRequest.setHttpMethod(getHttpMethod());
	    clientRequest.header("Content-Type", request.getContentType());
	    if (request.getAuthenticationMethod() == AuthenticationMethod.CLIENT_SECRET_BASIC && request.hasCredentials()) {
	        clientRequest.header("Authorization", "Basic " + request.getEncodedCredentials());
	    }


        new ClientAuthnEnabler(clientRequest, requestForm).exec(getRequest());

        // Call REST Service and handle response
        clientResponse = clientRequest.buildPost(Entity.form(requestForm)).invoke();

        setResponse(new BackchannelAuthenticationResponse(clientResponse));
        if (StringUtils.isNotBlank(response.getEntity())) {
            JSONObject jsonObj = new JSONObject(response.getEntity());

            if (jsonObj.has(AUTH_REQ_ID)) {
                getResponse().setAuthReqId(jsonObj.getString(AUTH_REQ_ID));
            }
            if (jsonObj.has(EXPIRES_IN)) {
                getResponse().setExpiresIn(jsonObj.getInt(EXPIRES_IN));
            }
            if (jsonObj.has(INTERVAL)) {
                getResponse().setInterval(jsonObj.getInt(INTERVAL));
            }
        }

        return getResponse();
    }
}