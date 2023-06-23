package org.gluu.stat.exporter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Yuriy Z
 */

@JsonIgnoreProperties(ignoreUnknown = true)
public class StatExporterConfig {

    @JsonProperty(value = "well-known-endpoint")
    private String wellKnownEndpoint;
    @JsonProperty(value = "client-id")
    private String clientId;
    @JsonProperty(value = "client-secret")
    private String clientSecret;

    public String getWellKnownEndpoint() {
        return wellKnownEndpoint;
    }

    public void setWellKnownEndpoint(String wellKnownEndpoint) {
        this.wellKnownEndpoint = wellKnownEndpoint;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}
