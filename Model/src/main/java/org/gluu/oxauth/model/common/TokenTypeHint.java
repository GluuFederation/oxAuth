/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import java.util.HashMap;
import java.util.Map;

import org.gluu.persist.annotation.AttributeEnum;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * @author Javier Rojas Blum
 * @version January 16, 2019
 */
public enum TokenTypeHint implements HasParamName, AttributeEnum {

    /**
     * An access token as defined in RFC6749, Section 1.4
     */
    ACCESS_TOKEN("access_token"),

    /**
     * A refresh token as defined in RFC6749, Section 1.5
     */
    REFRESH_TOKEN("refresh_token");

    private final String value;

    private static Map<String, TokenTypeHint> mapByValues = new HashMap<String, TokenTypeHint>();

    static {
        for (TokenTypeHint enumType : values()) {
            mapByValues.put(enumType.getValue(), enumType);
        }
    }

    TokenTypeHint(String value) {
        this.value = value;
    }

    /**
     * Gets param name.
     *
     * @return param name
     */
    @Override
    public String getParamName() {
        return value;
    }

    @Override
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static TokenTypeHint fromString(String param) {
        if (param != null) {
            for (TokenTypeHint tth : TokenTypeHint.values()) {
                if (param.equals(tth.value)) {
                    return tth;
                }
            }
        }
        return null;
    }

    public static TokenTypeHint getByValue(String value) {
        return mapByValues.get(value);
    }

    @Override
    public Enum<? extends AttributeEnum> resolveByValue(String s) {
        return getByValue(value);
    }

    /**
     * Returns a string representation of the object. In this case the parameter
     * name for the grant_type parameter.
     *
     * @return The string representation of the object.
     */
    @Override
    @JsonValue
    public String toString() {
        return value;
    }
}
