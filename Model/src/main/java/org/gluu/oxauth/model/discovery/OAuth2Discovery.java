package org.gluu.oxauth.model.discovery;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.jboss.resteasy.annotations.providers.jaxb.IgnoreMediaTypes;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;

/**
 * OAuth discovery
 *
 * @author yuriyz on 05/17/2017.
 */
@IgnoreMediaTypes("application/*+json")
// try to ignore jettison as it's recommended here: http://docs.jboss.org/resteasy/docs/2.3.4.Final/userguide/html/json.html
@JsonPropertyOrder({
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "registration_endpoint",
        "response_types_supported",
        "response_modes_supported",
        "grant_types_supported",
        "token_endpoint_auth_methods_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "service_documentation",
        "ui_locales_supported",
        "op_policy_uri",
        "op_tos_uri",
        "revocation_endpoint",
        "revocation_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
        "introspection_endpoint",
        "introspection_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_signing_alg_values_supported",
        "code_challenge_methods_supported"
})
@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class OAuth2Discovery {

    @JsonProperty(value = "issuer")
    @XmlElement(name = "issuer")
    private String issuer;

    @JsonProperty(value = "authorization_endpoint")
    @XmlElement(name = "authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty(value = "token_endpoint")
    @XmlElement(name = "token_endpoint")
    private String tokenEndpoint;

    @JsonProperty(value = "jwks_uri")
    @XmlElement(name = "jwks_uri")
    private String jwksUri;

    @JsonProperty(value = "registration_endpoint")
    @XmlElement(name = "registration_endpoint")
    private String registrationEndpoint;

    @JsonProperty(value = "response_types_supported")
    @XmlElement(name = "response_types_supported")
    private String[] responseTypesSupported;

//    @JsonProperty(value = "response_modes_supported")
//    @XmlElement(name = "response_modes_supported")
//    private String[] responseModesSupported;

    @JsonProperty(value = "grant_types_supported")
    @XmlElement(name = "grant_types_supported")
    private String[] grantTypesSupported;

    @JsonProperty(value = "token_endpoint_auth_methods_supported")
    @XmlElement(name = "token_endpoint_auth_methods_supported")
    private String[] tokenEndpointAuthMethodsSupported;

    @JsonProperty(value = "token_endpoint_auth_signing_alg_values_supported")
    @XmlElement(name = "token_endpoint_auth_signing_alg_values_supported")
    private String[] tokenEndpointAuthSigningAlgValuesSupported;

    @JsonProperty(value = "service_documentation")
    @XmlElement(name = "service_documentation")
    private String serviceDocumentation;

    @JsonProperty(value = "ui_locales_supported")
    @XmlElement(name = "ui_locales_supported")
    private String[] uiLocalesSupported;

    @JsonProperty(value = "op_policy_uri")
    @XmlElement(name = "op_policy_uri")
    private String opPolicyUri;

    @JsonProperty(value = "op_tos_uri")
    @XmlElement(name = "op_tos_uri")
    private String opTosUri;

//    @JsonProperty(value = "revocation_endpoint")
//    @XmlElement(name = "revocation_endpoint")
//    private String revocationEndpoint;
//
//    @JsonProperty(value = "revocation_endpoint_auth_methods_supported")
//    @XmlElement(name = "revocation_endpoint_auth_methods_supported")
//    private String[] revocation_endpoint_auth_methods_supported;
//
//    @JsonProperty(value = "revocation_endpoint_auth_signing_alg_values_supported")
//    @XmlElement(name = "revocation_endpoint_auth_signing_alg_values_supported")
//    private String[] revocationEndpointAuthSigningAlgValuesSupported;

    @JsonProperty(value = "introspection_endpoint")
    @XmlElement(name = "introspection_endpoint")
    private String introspectionEndpoint;

//    @JsonProperty(value = "introspection_endpoint_auth_methods_supported")
//    @XmlElement(name = "introspection_endpoint_auth_methods_supported")
//    private String[] introspectionEndpointAuthMethodsSupported;
//
//    @JsonProperty(value = "introspection_endpoint_auth_signing_alg_values_supported")
//    @XmlElement(name = "introspection_endpoint_auth_signing_alg_values_supported")
//    private String[] introspectionEndpointAuthSigningAlgValuesSupported;

    @JsonProperty(value = "code_challenge_methods_supported")
    @XmlElement(name = "code_challenge_methods_supported")
    private String[] codeChallengeMethodsSupported;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String[] getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public void setResponseTypesSupported(String[] responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

//    public String[] getResponseModesSupported() {
//        return responseModesSupported;
//    }
//
//    public void setResponseModesSupported(String[] responseModesSupported) {
//        this.responseModesSupported = responseModesSupported;
//    }

    public String[] getGrantTypesSupported() {
        return grantTypesSupported;
    }

    public void setGrantTypesSupported(String[] grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
    }

    public String[] getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public void setTokenEndpointAuthMethodsSupported(String[] tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    public String[] getTokenEndpointAuthSigningAlgValuesSupported() {
        return tokenEndpointAuthSigningAlgValuesSupported;
    }

    public void setTokenEndpointAuthSigningAlgValuesSupported(String[] tokenEndpointAuthSigningAlgValuesSupported) {
        this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
    }

    public String getServiceDocumentation() {
        return serviceDocumentation;
    }

    public void setServiceDocumentation(String serviceDocumentation) {
        this.serviceDocumentation = serviceDocumentation;
    }

    public String[] getUiLocalesSupported() {
        return uiLocalesSupported;
    }

    public void setUiLocalesSupported(String[] uiLocalesSupported) {
        this.uiLocalesSupported = uiLocalesSupported;
    }

    public String getOpPolicyUri() {
        return opPolicyUri;
    }

    public void setOpPolicyUri(String opPolicyUri) {
        this.opPolicyUri = opPolicyUri;
    }

    public String getOpTosUri() {
        return opTosUri;
    }

    public void setOpTosUri(String opTosUri) {
        this.opTosUri = opTosUri;
    }

//    public String getRevocationEndpoint() {
//        return revocationEndpoint;
//    }
//
//    public void setRevocationEndpoint(String revocationEndpoint) {
//        this.revocationEndpoint = revocationEndpoint;
//    }
//
//    public String[] getRevocation_endpoint_auth_methods_supported() {
//        return revocation_endpoint_auth_methods_supported;
//    }
//
//    public void setRevocation_endpoint_auth_methods_supported(String[] revocation_endpoint_auth_methods_supported) {
//        this.revocation_endpoint_auth_methods_supported = revocation_endpoint_auth_methods_supported;
//    }
//
//    public String[] getRevocationEndpointAuthSigningAlgValuesSupported() {
//        return revocationEndpointAuthSigningAlgValuesSupported;
//    }
//
//    public void setRevocationEndpointAuthSigningAlgValuesSupported(String[] revocationEndpointAuthSigningAlgValuesSupported) {
//        this.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported;
//    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }

//    public String[] getIntrospectionEndpointAuthMethodsSupported() {
//        return introspectionEndpointAuthMethodsSupported;
//    }
//
//    public void setIntrospectionEndpointAuthMethodsSupported(String[] introspectionEndpointAuthMethodsSupported) {
//        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
//    }
//
//    public String[] getIntrospectionEndpointAuthSigningAlgValuesSupported() {
//        return introspectionEndpointAuthSigningAlgValuesSupported;
//    }
//
//    public void setIntrospectionEndpointAuthSigningAlgValuesSupported(String[] introspectionEndpointAuthSigningAlgValuesSupported) {
//        this.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported;
//    }

    public String[] getCodeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    public void setCodeChallengeMethodsSupported(String[] codeChallengeMethodsSupported) {
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
    }

    @Override
    public String toString() {
        return "OAuth2Discovery{" +
                "issuer='" + issuer + '\'' +
                ", authorizationEndpoint='" + authorizationEndpoint + '\'' +
                ", tokenEndpoint='" + tokenEndpoint + '\'' +
                ", jwksUri='" + jwksUri + '\'' +
                ", registrationEndpoint='" + registrationEndpoint + '\'' +
                ", responseTypesSupported=" + Arrays.toString(responseTypesSupported) +
//                ", responseModesSupported=" + Arrays.toString(responseModesSupported) +
                ", grantTypesSupported=" + Arrays.toString(grantTypesSupported) +
                ", tokenEndpointAuthMethodsSupported=" + Arrays.toString(tokenEndpointAuthMethodsSupported) +
                ", tokenEndpointAuthSigningAlgValuesSupported=" + Arrays.toString(tokenEndpointAuthSigningAlgValuesSupported) +
                ", serviceDocumentation='" + serviceDocumentation + '\'' +
                ", uiLocalesSupported=" + Arrays.toString(uiLocalesSupported) +
                ", opPolicyUri='" + opPolicyUri + '\'' +
                ", opTosUri='" + opTosUri + '\'' +
//                ", revocationEndpoint='" + revocationEndpoint + '\'' +
//                ", revocation_endpoint_auth_methods_supported=" + Arrays.toString(revocation_endpoint_auth_methods_supported) +
//                ", revocationEndpointAuthSigningAlgValuesSupported=" + Arrays.toString(revocationEndpointAuthSigningAlgValuesSupported) +
                ", introspectionEndpoint='" + introspectionEndpoint + '\'' +
//                ", introspectionEndpointAuthMethodsSupported=" + Arrays.toString(introspectionEndpointAuthMethodsSupported) +
//                ", introspectionEndpointAuthSigningAlgValuesSupported=" + Arrays.toString(introspectionEndpointAuthSigningAlgValuesSupported) +
                ", codeChallengeMethodsSupported=" + Arrays.toString(codeChallengeMethodsSupported) +
                '}';
    }
}
