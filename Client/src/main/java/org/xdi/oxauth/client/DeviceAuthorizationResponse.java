/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client;

import org.apache.commons.lang.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.jboss.resteasy.client.ClientResponse;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceErrorResponseType;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceResponseParam;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public class DeviceAuthorizationResponse extends BaseResponse {

    private String deviceCode;
    private String userCode;
    private String verificationUri;
    private Integer expiresIn;
    private Integer interval;

    private AuthorizeDeviceErrorResponseType errorType;
    private String errorDescription;
    private String errorUri;

    public DeviceAuthorizationResponse(ClientResponse<String> clientResponse) {
        super(clientResponse);

        if (StringUtils.isNotBlank(entity)) {
            try {
                JSONObject jsonObj = new JSONObject(entity);

                if (jsonObj.has(AuthorizeDeviceResponseParam.DEVICE_CODE)) {
                    deviceCode = jsonObj.getString(AuthorizeDeviceResponseParam.DEVICE_CODE);
                }
                if (jsonObj.has(AuthorizeDeviceResponseParam.USER_CODE)) {
                    userCode = jsonObj.getString(AuthorizeDeviceResponseParam.USER_CODE);
                }
                if (jsonObj.has(AuthorizeDeviceResponseParam.VERIFICATION_URI)) {
                    verificationUri = jsonObj.getString(AuthorizeDeviceResponseParam.VERIFICATION_URI);
                }
                if (jsonObj.has(AuthorizeDeviceResponseParam.EXPIRES_IN)) {
                    expiresIn = jsonObj.getInt(AuthorizeDeviceResponseParam.EXPIRES_IN);
                }
                if (jsonObj.has(AuthorizeDeviceResponseParam.INTERVAL)) {
                    interval = jsonObj.getInt(AuthorizeDeviceResponseParam.INTERVAL);
                }

                if (jsonObj.has(AuthorizeDeviceResponseParam.ERROR)) {
                    errorType = AuthorizeDeviceErrorResponseType.fromString(jsonObj.getString(AuthorizeDeviceResponseParam.ERROR));
                }
                if (jsonObj.has(AuthorizeDeviceResponseParam.ERROR_DESCRIPTION)) {
                    errorDescription = jsonObj.getString(AuthorizeDeviceResponseParam.ERROR_DESCRIPTION);
                }
                if (jsonObj.has(AuthorizeDeviceResponseParam.ERROR_URI)) {
                    errorUri = jsonObj.getString(AuthorizeDeviceResponseParam.ERROR_URI);
                }
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
    }

    public String getDeviceCode() {
        return deviceCode;
    }

    public String getUserCode() {
        return userCode;
    }

    public String getVerificationUri() {
        return verificationUri;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public Integer getInterval() {
        return interval;
    }

    public AuthorizeDeviceErrorResponseType getErrorType() {
        return errorType;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String getErrorUri() {
        return errorUri;
    }
}
