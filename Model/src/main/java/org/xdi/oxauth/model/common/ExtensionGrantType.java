/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.common;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public interface ExtensionGrantType {

    public static final String SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
    public static final String DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
}
