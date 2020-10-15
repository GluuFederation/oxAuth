/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.register;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.gluu.persist.annotation.AttributeEnum;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Javier Rojas Blum Date: 01.12.2012
 */
public enum ApplicationType implements AttributeEnum {

    /**
     * Clients incapable of maintaining the confidentiality of their credentials
     * (e.g. clients executing on the resource owner's device such as an
     * installed native application or a web browser-based application), and
     * incapable of secure client authentication via any other mean.
     */
    NATIVE("native"),

    /**
     * Clients capable of maintaining the confidentiality of their credentials
     * (e.g. client implemented on a secure server with restricted access to the
     * client credentials), or capable of secure client authentication using
     * other means.
     */
    WEB("web");

    private static Map<String, ApplicationType> mapByValues = new HashMap<>();

    static {
        for (ApplicationType enumType : values()) {
            mapByValues.put(enumType.getValue(), enumType);
        }
    }

    private final String paramName;

    private ApplicationType(String paramName) {
        this.paramName = paramName;
    }

    /**
     * Returns the corresponding {@link ApplicationType} from a given string.
     * The default if not specified is web.
     *
     * @param param The string value to convert.
     * @return The corresponding {@link ApplicationType}, otherwise <code>null</code>.
     */
    @JsonCreator
    public static ApplicationType fromString(String param) {
        if (param != null) {
            for (ApplicationType at : ApplicationType.values()) {
                if (param.equals(at.paramName)) {
                    return at;
                }
            }
        }
        return WEB;
    }

    public static ApplicationType getByValue(String value) {
        return mapByValues.get(value);
    }

    /**
     * Returns a string representation of the object. In this case the parameter name.
     *
     * @return The string representation of the object.
     */
    @Override
    @JsonValue
    public String toString() {
        return paramName;
    }

    public String getValue() {
        return paramName;
    }

    public Enum<? extends AttributeEnum> resolveByValue(String value) {
        return getByValue(value);
    }
}