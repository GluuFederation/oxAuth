package org.gluu.oxauth.model.session;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Yuriy Z
 */
public class AuthorizationChallengeSessionAttributes {

    @JsonProperty("acr_values")
    private String acrValues;

    @JsonProperty("attributes")
    private Map<String, String> attributes;

    public Map<String, String> getAttributes() {
        if (attributes == null) attributes = new HashMap<>();
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public String getAcrValues() {
        return acrValues;
    }

    public void setAcrValues(String acrValues) {
        this.acrValues = acrValues;
    }

    @Override
    public String toString() {
        return "AuthorizationChallengeSessionAttributes{" +
                "acrValues='" + acrValues + '\'' +
                "attributes='" + attributes + '\'' +
                '}';
    }
}
