package org.gluu.stat.exporter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Yuriy Z
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RegisterRequest {

    @JsonProperty(value = "application_type")
    private String applicationType = "web";
    @JsonProperty(value = "redirect_uris")
    private List<String> redirectUris = new ArrayList<>();
    @JsonProperty(value = "scope")
    private String scope;
    @JsonProperty(value = "grant_types")
    private List<String> grantTypes;
    @JsonProperty(value = "client_name")
    private String clientName;

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getApplicationType() {
        return applicationType;
    }

    public void setApplicationType(String applicationType) {
        this.applicationType = applicationType;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    @Override
    public String toString() {
        return "RegisterRequest{" +
                "applicationType='" + applicationType + '\'' +
                ", redirectUris=" + redirectUris +
                ", scope='" + scope + '\'' +
                ", grantTypes='" + grantTypes + '\'' +
                ", clientName='" + clientName + '\'' +
                '}';
    }
}
