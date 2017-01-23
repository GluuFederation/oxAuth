/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client;

import org.apache.commons.lang.StringUtils;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceRequestParam;
import org.xdi.oxauth.model.common.AuthorizationMethod;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxauth.model.util.Util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public class DeviceAuthorizationRequest extends BaseRequest {

    private String clientId;
    private List<String> scopes;
    private ResponseType responseType = ResponseType.DEVICE_CODE;

    public DeviceAuthorizationRequest(String clientId, List<String> scopes) {
        super();

        this.clientId = clientId;
        this.scopes = scopes;

        setAuthorizationMethod(AuthorizationMethod.FORM_ENCODED_BODY_PARAMETER);
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public String getScopesAsString() {
        return Util.listAsString(scopes);
    }

    public ResponseType getResponseType() {
        return responseType;
    }

    @Override
    public String getQueryString() {
        StringBuilder queryStringBuilder = new StringBuilder();

        try {
            final String scopesAsString = getScopesAsString();

            queryStringBuilder.append(AuthorizeDeviceRequestParam.RESPONSE_TYPE)
                    .append("=").append(responseType);
            if (StringUtils.isNotBlank(clientId)) {
                queryStringBuilder.append("&").append(AuthorizeDeviceRequestParam.CLIENT_ID)
                        .append("=").append(URLEncoder.encode(clientId, Util.UTF8_STRING_ENCODING));
            }
            if (StringUtils.isNotBlank(scopesAsString)) {
                queryStringBuilder.append("&").append(AuthorizeDeviceRequestParam.SCOPE)
                        .append("=").append(URLEncoder.encode(scopesAsString, Util.UTF8_STRING_ENCODING));
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return queryStringBuilder.toString();
    }
}
