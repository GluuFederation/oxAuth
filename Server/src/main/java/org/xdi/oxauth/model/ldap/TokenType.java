/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.ldap;

import org.apache.commons.lang.StringUtils;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public enum TokenType {
    ID_TOKEN("id_token"),
    ACCESS_TOKEN("access_token"),
    LONG_LIVED_ACCESS_TOKEN("access_token"),
    REFRESH_TOKEN("refresh_token"),
    AUTHORIZATION_CODE("authorization_code"),
    DEVICE_CODE("device_code");

    private final String value;

    TokenType(String name) {
        value = name;
    }

    public String getValue() {
        return value;
    }

    public static TokenType fromValue(String value) {
        if (StringUtils.isNotBlank(value)) {
            for (TokenType t : values()) {
                if (t.getValue().endsWith(value)) {
                    return t;
                }
            }
        }
        return null;
    }
}
