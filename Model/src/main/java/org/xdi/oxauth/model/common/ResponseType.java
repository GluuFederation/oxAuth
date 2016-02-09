/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.common;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.gluu.site.ldap.persistence.annotation.LdapEnum;

/**
 * <p>
 * This class allows to enumerate and identify the possible values of the
 * parameter response_type for the authorization endpoint.
 * </p>
 * <p>
 * The client informs the authorization server of the desired grant type.
 * </p>
 * <p>
 * The authorization endpoint is used by the authorization code grant type and
 * implicit grant type flows.
 * </p>
 *
 * @author Javier Rojas Blum Date: 09.20.2011
 */
public enum ResponseType implements HasParamName, LdapEnum {

    /**
     * Used for the authorization code grant type.
     */
    CODE("code", "Authorization Code Grant Type"),
    /**
     * Used for the implicit grant type.
     */
    TOKEN("token", "Implicit Grant Type"),
    /**
     * Include an ID Token in the authorization response.
     */
    ID_TOKEN("id_token", "ID Token");

    private final String value;
	private final String displayName;

	private static Map<String, ResponseType> mapByValues = new HashMap<String, ResponseType>();

	static {
		for (ResponseType enumType : values()) {
			mapByValues.put(enumType.getValue(), enumType);
		}
	}

    private ResponseType(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    /**
     * Returns the corresponding {@link ResponseType} for a single parameter response_type.
     *
     * @param param The response_type parameter.
     * @return The corresponding response type if found, otherwise <code>null</code>.
     */
    public static ResponseType fromString(String param) {
    	return getByValue(param);
    }

    /**
     * Gets param name.
     *
     * @return param name
     */
    public String getParamName() {
        return value;
    }

    /**
     * Gets display name
     *
     * @return display name name
     */
    public String getDisplayName() {
		return displayName;
	}

	@Override
	public String getValue() {
		return value;
	}

	/**
     * Returns a list of the corresponding {@link ResponseType} from a space-separated
     * list of response_type parameters.
     *
     * @param paramList A space-separated list of response_type parameters.
     * @param separator The separator of the string list.
     * @return A list of the recognized response types.
     */
    public static List<ResponseType> fromString(String paramList, String separator) {
        List<ResponseType> responseTypes = new ArrayList<ResponseType>();

        if (paramList != null && !paramList.isEmpty()) {
            String[] params = paramList.split(separator);
            for (String param : params) {
                for (ResponseType rt : ResponseType.values()) {
                    if (param.equals(rt.value) && !responseTypes.contains(rt)) {
                        responseTypes.add(rt);
                    }
                }
            }
        }

        return responseTypes;
    }

	public static String[] toStringArray(ResponseType[] responseTypes) {
		if (responseTypes == null) {
			return null;
		}

		String[] resultResponseTypes = new String[responseTypes.length];
		for (int i = 0; i < responseTypes.length; i++) {
			resultResponseTypes[i] = responseTypes[i].getValue();
		}

		return resultResponseTypes;
	}

	public static ResponseType getByValue(String value) {
		return mapByValues.get(value);
	}

	public Enum<? extends LdapEnum> resolveByValue(String value) {
		return getByValue(value);
	}

    /**
     * Returns a string representation of the object. In this case the parameter
     * name for the response_type parameter.
     */
    @Override
    public String toString() {
        return value;
    }

}