/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.authorize;

import org.xdi.oxauth.model.error.IErrorType;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public enum AuthorizeDeviceErrorResponseType implements IErrorType {

    /**
     * The request is missing a required parameter, includes an unsupported parameter value or is otherwise malformed.
     */
    INVALID_REQUEST("invalid_request"),

    /**
     * The requested scope is invalid, unknown, or malformed.
     */
    INVALID_SCOPE("invalid_scope");

    private final String paramName;

    private AuthorizeDeviceErrorResponseType(String paramName) {
        this.paramName = paramName;
    }

    /**
     * Return the corresponding enumeration from a string parameter.
     *
     * @param param The parameter to be match.
     * @return The <code>enumeration</code> if found, otherwise <code>null</code>.
     */
    public static AuthorizeDeviceErrorResponseType fromString(String param) {
        if (param != null) {
            for (AuthorizeDeviceErrorResponseType err : AuthorizeDeviceErrorResponseType
                    .values()) {
                if (param.equals(err.paramName)) {
                    return err;
                }
            }
        }
        return null;
    }


    /**
     * Returns a string representation of the object. In this case, the lower case code of the error.
     */
    @Override
    public String toString() {
        return paramName;
    }

    /**
     * Gets error parameter.
     *
     * @return error parameter
     */
    @Override
    public String getParameter() {
        return paramName;
    }
}
