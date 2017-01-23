/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.authorize;

import org.xdi.oxauth.model.common.ErrorResponseParam;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public interface AuthorizeDeviceResponseParam extends ErrorResponseParam {

    /**
     * The verification code.
     */
    public static final String DEVICE_CODE = "device_code";

    /**
     * The end-user verification code.
     */
    public static final String USER_CODE = "user_code";

    /**
     * The end-user verification URI on the authorization server.
     * The URI is short and easy to remember as end-users will be asked to manually type it into their user-agent.
     */
    public static final String VERIFICATION_URI = "verification_uri";

    /**
     * The duration in seconds of the verification code lifetime.
     */
    public static final String EXPIRES_IN = "expires_in";

    /**
     * The minimum amount of time in seconds that the client should wait between polling requests to the token endpoint.
     */
    public static final String INTERVAL = "interval";
}
