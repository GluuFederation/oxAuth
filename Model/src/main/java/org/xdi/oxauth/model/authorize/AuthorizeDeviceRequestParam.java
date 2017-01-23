/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.authorize;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public interface AuthorizeDeviceRequestParam {

    /**
     * The parameter Response Type value must be set to "device_code".
     */
    public static final String RESPONSE_TYPE = "response_type";

    /**
     * The client identifier.
     */
    public static final String CLIENT_ID = "client_id";

    /**
     * The scope of the access request.
     */
    public static final String SCOPE = "scope";
}
