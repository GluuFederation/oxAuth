/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.gluu.persist.annotation.AttributeEnum;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Javier Rojas Blum Date: 05.11.2012
 */
public enum SubjectType implements AttributeEnum {

    PAIRWISE("pairwise"),
    PUBLIC("public");
    private static Map<String, SubjectType> mapByValues = new HashMap<>();

    static {
        for (SubjectType enumType : values()) {
            mapByValues.put(enumType.getValue(), enumType);
        }
    }

    private final String paramName;

    private SubjectType(String paramName) {
        this.paramName = paramName;
    }

    /**
     * Returns the corresponding {@link SubjectType} for an user id type parameter.
     *
     * @param param The parameter.
     * @return The corresponding user id type if found, otherwise
     * <code>null</code>.
     */
    @JsonCreator
    public static SubjectType fromString(String param) {
        if (param != null) {
            for (SubjectType uit : SubjectType.values()) {
                if (param.equals(uit.paramName)) {
                    return uit;
                }
            }
        }
        return null;
    }

    public static SubjectType getByValue(String value) {
        return mapByValues.get(value);
    }

    /**
     * Returns a string representation of the object. In this case the parameter
     * name for the user id type parameter.
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