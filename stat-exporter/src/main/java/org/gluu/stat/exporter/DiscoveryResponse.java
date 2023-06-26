package org.gluu.stat.exporter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Yuriy Z
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DiscoveryResponse {

    @JsonProperty(value = "issuer")
    private String issuer;
    @JsonProperty(value = "token_endpoint")
    private String tokenEndpoint;
    @JsonProperty(value = "registration_endpoint")
    private String registrationEndpoint;

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    @Override
    public String toString() {
        return "DiscoveryResponse{" +
                "issuer='" + issuer + '\'' +
                ", tokenEndpoint='" + tokenEndpoint + '\'' +
                ", registrationEndpoint='" + registrationEndpoint + '\'' +
                '}';
    }
}
