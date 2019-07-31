/*
 * oxAuth-CIBA is available under the Gluu Enterprise License (2019).
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client.push;

import org.apache.commons.lang.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.xdi.oxauth.client.BaseRequest;
import org.xdi.oxauth.model.common.TokenType;

import static org.xdi.oxauth.model.ciba.PushTokenDeliveryRequestParam.*;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
public class PushTokenDeliveryRequest extends BaseRequest {

    private String clientNotificationToken;
    private String authorizationRequestId;
    private String accessToken;
    private TokenType tokenType;
    private String refreshToken;
    private Integer expiresIn;
    private String idToken;

    public String getClientNotificationToken() {
        return clientNotificationToken;
    }

    public void setClientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
    }

    public String getAuthorizationRequestId() {
        return authorizationRequestId;
    }

    public void setAuthorizationRequestId(String authorizationRequestId) {
        this.authorizationRequestId = authorizationRequestId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Integer expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    @Override
    public JSONObject getJSONParameters() throws JSONException {
        JSONObject parameters = new JSONObject();

        if (StringUtils.isNotBlank(authorizationRequestId)) {
            parameters.put(AUTHORIZATION_REQUEST_ID, authorizationRequestId);
        }

        if (StringUtils.isNotBlank(accessToken)) {
            parameters.put(ACCESS_TOKEN, accessToken);
        }

        if (tokenType != null) {
            parameters.put(TOKEN_TYPE, tokenType.getName());
        }

        if (StringUtils.isNotBlank(refreshToken)) {
            parameters.put(REFRESH_TOKEN, refreshToken);
        }

        if (expiresIn != null) {
            parameters.put(EXPIRES_IN, expiresIn);
        }

        if (StringUtils.isNotBlank(idToken)) {
            parameters.put(ID_TOKEN, idToken);
        }

        return parameters;
    }

    @Override
    public String getQueryString() {
        String jsonQueryString = null;

        try {
            jsonQueryString = getJSONParameters().toString(4).replace("\\/", "/");
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return jsonQueryString;
    }
}
