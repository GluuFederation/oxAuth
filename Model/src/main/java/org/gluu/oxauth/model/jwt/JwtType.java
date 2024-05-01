/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.jwt;

/**
 * @author Javier Rojas Blum
 * @version December 17, 2015
 */
public enum JwtType {

    JWT("JWT");

    private final String paramName;

    JwtType(String paramName) {
        this.paramName = paramName;
    }

    /**
     * Returns the corresponding {@link JwtType} for a parameter.
     *
     * @param param The parameter.
     * @return The corresponding JWT Type if found, otherwise <code>null</code>.
     */
    public static JwtType fromString(String param) {
        if (param != null) {
            for (JwtType t : JwtType.values()) {
                if (param.equals(t.toString())) {
                    return t;
                }
            }
        }
        return null;
    }

    public String getParamName() {
        return paramName;
    }

    @Override
    public String toString() {
        return paramName;
    }
}