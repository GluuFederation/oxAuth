/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.configuration;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.xdi.oxauth.model.common.WebKeyStorage;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Represents the configuration JSON file.
 *
 * @author Javier Rojas Blum
 * @author Yuriy Zabrovarnyy
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AppConfiguration {

    private String issuer;
    private String loginPage;
    private String authorizationPage;
    private String baseEndpoint;
    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String userInfoEndpoint;
    private String clientInfoEndpoint;
    private String checkSessionIFrame;
    private String endSessionEndpoint;
    private String jwksUri;
    private String registrationEndpoint;
    private String validateTokenEndpoint;
    private String openIdDiscoveryEndpoint;
    private String openIdConfigurationEndpoint;
    private String idGenerationEndpoint;
    private String introspectionEndpoint;

    private Boolean sessionAsJwt = false;

    private String umaConfigurationEndpoint;
    private Boolean umaRptAsJwt = false;
    private int umaRequesterPermissionTokenLifetime;
    private Boolean umaAddScopesAutomatically;
    private Boolean umaKeepClientDuringResourceSetRegistration;

    private String openidSubAttribute;
    private List<String> responseTypesSupported;
    private List<String> grantTypesSupported;
    private List<String> subjectTypesSupported;
    private String defaultSubjectType;
    private List<String> userInfoSigningAlgValuesSupported;
    private List<String> userInfoEncryptionAlgValuesSupported;
    private List<String> userInfoEncryptionEncValuesSupported;
    private List<String> idTokenSigningAlgValuesSupported;
    private List<String> idTokenEncryptionAlgValuesSupported;
    private List<String> idTokenEncryptionEncValuesSupported;
    private List<String> requestObjectSigningAlgValuesSupported;
    private List<String> requestObjectEncryptionAlgValuesSupported;
    private List<String> requestObjectEncryptionEncValuesSupported;
    private List<String> tokenEndpointAuthMethodsSupported;
    private List<String> tokenEndpointAuthSigningAlgValuesSupported;
    private List<String> dynamicRegistrationCustomAttributes;
    private List<String> displayValuesSupported;
    private List<String> claimTypesSupported;
    private String serviceDocumentation;
    private List<String> claimsLocalesSupported;
    private List<String> uiLocalesSupported;
    private Boolean claimsParameterSupported;
    private Boolean requestParameterSupported;
    private Boolean requestUriParameterSupported;
    private Boolean requireRequestUriRegistration;
    private String opPolicyUri;
    private String opTosUri;
    private int authorizationCodeLifetime;
    private int refreshTokenLifetime;
    private int idTokenLifetime;
    private int shortLivedAccessTokenLifetime;
    private int longLivedAccessTokenLifetime;

    private int cleanServiceInterval;
    private Boolean keyRegenerationEnabled;
    private int keyRegenerationInterval;
    private String defaultSignatureAlgorithm;
    private String oxOpenIdConnectVersion;
    private String organizationInum;
    private String oxId;
    private Boolean dynamicRegistrationEnabled;
    private int dynamicRegistrationExpirationTime;
    private Boolean dynamicRegistrationPersistClientAuthorizations;
    private Boolean trustedClientEnabled;
    private Boolean dynamicRegistrationScopesParamEnabled;
    private String dynamicRegistrationCustomObjectClass;

    private Boolean authenticationFiltersEnabled;
    private Boolean clientAuthenticationFiltersEnabled;
    private List<AuthenticationFilter> authenticationFilters;
    private List<ClientAuthenticationFilter> clientAuthenticationFilters;
    private List<CorsConfigurationFilter> corsConfigurationFilters;

    private String applianceInum;
    private int sessionIdUnusedLifetime;
    private int sessionIdUnauthenticatedUnusedLifetime = 120; // 120 seconds
    private Boolean sessionIdEnabled;
    private Boolean sessionIdPersistOnPromptNone;
    /**
     * SessionId will be expired after sessionIdLifetime seconds
     */
    private Integer sessionIdLifetime = 86400;
    private int configurationUpdateInterval;

    private String cssLocation;
    private String jsLocation;
    private String imgLocation;
    private int metricReporterInterval;
    private int metricReporterKeepDataDays;
    private String pairwiseIdType; // persistent, algorithmic
    private String pairwiseCalculationKey;
    private String pairwiseCalculationSalt;

    private WebKeyStorage webKeysStorage;
    private String dnName;
    // oxAuth KeyStore
    private String keyStoreFile;
    private String keyStoreSecret;
    //oxEleven
    private String oxElevenGenerateKeyEndpoint;
    private String oxElevenSignEndpoint;
    private String oxElevenVerifySignatureEndpoint;
    private String oxElevenDeleteKeyEndpoint;

    private Boolean endSessionWithAccessToken;
    private Boolean enabledOAuthAuditLogging;
    private Set<String> jmsBrokerURISet;
    private String jmsUserName;
    private String jmsPassword;
    private List<String> clientWhiteList;
    private List<String> clientBlackList;
    private Boolean legacyIdTokenClaims;
    private Boolean customHeadersWithAuthorizationResponse;
    private Boolean frontChannelLogoutSessionSupported;
    private String loggingLevel;
    private Boolean updateUserLastLogonTime;
    private Boolean updateClientAccessTime;

    public Boolean getFrontChannelLogoutSessionSupported() {
        return frontChannelLogoutSessionSupported;
    }

    public void setFrontChannelLogoutSessionSupported(
            Boolean frontChannelLogoutSessionSupported) {
        this.frontChannelLogoutSessionSupported = frontChannelLogoutSessionSupported;
    }

    public Boolean getUmaRptAsJwt() {
        return umaRptAsJwt;
    }

    public void setUmaRptAsJwt(Boolean umaRptAsJwt) {
        this.umaRptAsJwt = umaRptAsJwt;
    }

    public Boolean getSessionAsJwt() {
        return sessionAsJwt;
    }

    public void setSessionAsJwt(Boolean sessionAsJwt) {
        this.sessionAsJwt = sessionAsJwt;
    }

    public Boolean getUmaKeepClientDuringResourceSetRegistration() {
        return umaKeepClientDuringResourceSetRegistration;
    }

    public void setUmaKeepClientDuringResourceSetRegistration(Boolean p_umaKeepClientDuringResourceSetRegistration) {
        umaKeepClientDuringResourceSetRegistration = p_umaKeepClientDuringResourceSetRegistration;
    }

    public Boolean getUmaAddScopesAutomatically() {
        return umaAddScopesAutomatically;
    }

    public void setUmaAddScopesAutomatically(Boolean p_umaAddScopesAutomatically) {
        umaAddScopesAutomatically = p_umaAddScopesAutomatically;
    }

    /**
     * Returns the issuer identifier.
     *
     * @return The issuer identifier.
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the issuer identifier.
     *
     * @param issuer The issuer identifier.
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Returns the URL od the login page.
     *
     * @return The URL of the login page.
     */
    public String getLoginPage() {
        return loginPage;
    }

    /**
     * Sets the URL of the login page.
     *
     * @param loginPage The URL of the login page.
     */
    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    /**
     * Returns the URL of the authorization page.
     *
     * @return The URL of the authorization page.
     */
    public String getAuthorizationPage() {
        return authorizationPage;
    }

    /**
     * Sets the URL of the authorization page.
     *
     * @param authorizationPage The URL of the authorization page.
     */
    public void setAuthorizationPage(String authorizationPage) {
        this.authorizationPage = authorizationPage;
    }

    /**
     * Returns the base URI of the endpoints.
     *
     * @return The base URI of endpoints.
     */
    public String getBaseEndpoint() {
        return baseEndpoint;
    }

    /**
     * Sets the base URI of the endpoints.
     *
     * @param baseEndpoint The base URI of the endpoints.
     */
    public void setBaseEndpoint(String baseEndpoint) {
        this.baseEndpoint = baseEndpoint;
    }

    /**
     * Returns the URL of the Authentication and Authorization endpoint.
     *
     * @return The URL of the Authentication and Authorization endpoint.
     */
    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    /**
     * Sets the URL of the Authentication and Authorization endpoint.
     *
     * @param authorizationEndpoint The URL of the Authentication and Authorization endpoint.
     */
    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    /**
     * Returns the URL of the Token endpoint.
     *
     * @return The URL of the Token endpoint.
     */
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     * Sets the URL of the Token endpoint.
     *
     * @param tokenEndpoint The URL of the Token endpoint.
     */
    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Returns the URL of the User Info endpoint.
     *
     * @return The URL of the User Info endpoint.
     */
    public String getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    /**
     * Sets the URL for the User Info endpoint.
     *
     * @param userInfoEndpoint The URL for the User Info endpoint.
     */
    public void setUserInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    /**
     * Returns the URL od the Client Info endpoint.
     *
     * @return The URL of the Client Info endpoint.
     */
    public String getClientInfoEndpoint() {
        return clientInfoEndpoint;
    }

    /**
     * Sets the URL for the Client Info endpoint.
     *
     * @param clientInfoEndpoint The URL for the Client Info endpoint.
     */
    public void setClientInfoEndpoint(String clientInfoEndpoint) {
        this.clientInfoEndpoint = clientInfoEndpoint;
    }

    /**
     * Returns the URL of an OP endpoint that provides a page to support cross-origin
     * communications for session state information with the RP client.
     *
     * @return The Check Session iFrame URL.
     */
    public String getCheckSessionIFrame() {
        return checkSessionIFrame;
    }

    /**
     * Sets the  URL of an OP endpoint that provides a page to support cross-origin
     * communications for session state information with the RP client.
     *
     * @param checkSessionIFrame The Check Session iFrame URL.
     */
    public void setCheckSessionIFrame(String checkSessionIFrame) {
        this.checkSessionIFrame = checkSessionIFrame;
    }

    /**
     * Returns the URL of the End Session endpoint.
     *
     * @return The URL of the End Session endpoint.
     */
    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    /**
     * Sets the URL of the End Session endpoint.
     *
     * @param endSessionEndpoint The URL of the End Session endpoint.
     */
    public void setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    /**
     * Returns the URL of the OP's JSON Web Key Set (JWK) document that contains the Server's signing key(s)
     * that are used for signing responses to the Client.
     * The JWK Set may also contain the Server's encryption key(s) that are used by the Client to encrypt
     * requests to the Server.
     *
     * @return The URL of the OP's JSON Web Key Set (JWK) document.
     */
    public String getJwksUri() {
        return jwksUri;
    }

    /**
     * Sets the URL of the OP's JSON Web Key Set (JWK) document that contains the Server's signing key(s)
     * that are used for signing responses to the Client.
     * The JWK Set may also contain the Server's encryption key(s) that are used by the Client to encrypt
     * requests to the Server.
     *
     * @param jwksUri The URL of the OP's JSON Web Key Set (JWK) document.
     */
    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    /**
     * Returns the URL of the Dynamic Client Registration endpoint.
     *
     * @return The URL of the Dynamic Client Registration endpoint.
     */
    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    /**
     * Sets the URL of the Dynamic Client Registration endpoint.
     *
     * @param registrationEndpoint The URL of the Dynamic Client Registration endpoint.
     */
    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String getValidateTokenEndpoint() {
        return validateTokenEndpoint;
    }

    public void setValidateTokenEndpoint(String validateTokenEndpoint) {
        this.validateTokenEndpoint = validateTokenEndpoint;
    }

    public String getOpenIdDiscoveryEndpoint() {
        return openIdDiscoveryEndpoint;
    }

    public void setOpenIdDiscoveryEndpoint(String openIdDiscoveryEndpoint) {
        this.openIdDiscoveryEndpoint = openIdDiscoveryEndpoint;
    }

    public String getUmaConfigurationEndpoint() {
        return umaConfigurationEndpoint;
    }

    public void setUmaConfigurationEndpoint(String p_umaConfigurationEndpoint) {
        umaConfigurationEndpoint = p_umaConfigurationEndpoint;
    }

    public String getOpenidSubAttribute() {
        return openidSubAttribute;
    }

    public void setOpenidSubAttribute(String openidSubAttribute) {
        this.openidSubAttribute = openidSubAttribute;
    }

    public String getIdGenerationEndpoint() {
        return idGenerationEndpoint;
    }

    public void setIdGenerationEndpoint(String p_idGenerationEndpoint) {
        idGenerationEndpoint = p_idGenerationEndpoint;
    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String p_introspectionEndpoint) {
        introspectionEndpoint = p_introspectionEndpoint;
    }

    public String getOpenIdConfigurationEndpoint() {
        return openIdConfigurationEndpoint;
    }

    public void setOpenIdConfigurationEndpoint(String openIdConfigurationEndpoint) {
        this.openIdConfigurationEndpoint = openIdConfigurationEndpoint;
    }

    public List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public void setResponseTypesSupported(List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    public List<String> getGrantTypesSupported() {
        return grantTypesSupported;
    }

    public void setGrantTypesSupported(List<String> grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
    }

    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public void setSubjectTypesSupported(List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    public String getDefaultSubjectType() {
        return defaultSubjectType;
    }

    public void setDefaultSubjectType(String defaultSubjectType) {
        this.defaultSubjectType = defaultSubjectType;
    }

    public List<String> getUserInfoSigningAlgValuesSupported() {
        return userInfoSigningAlgValuesSupported;
    }

    public void setUserInfoSigningAlgValuesSupported(List<String> userInfoSigningAlgValuesSupported) {
        this.userInfoSigningAlgValuesSupported = userInfoSigningAlgValuesSupported;
    }

    public List<String> getUserInfoEncryptionAlgValuesSupported() {
        return userInfoEncryptionAlgValuesSupported;
    }

    public void setUserInfoEncryptionAlgValuesSupported(List<String> userInfoEncryptionAlgValuesSupported) {
        this.userInfoEncryptionAlgValuesSupported = userInfoEncryptionAlgValuesSupported;
    }

    public List<String> getUserInfoEncryptionEncValuesSupported() {
        return userInfoEncryptionEncValuesSupported;
    }

    public void setUserInfoEncryptionEncValuesSupported(List<String> userInfoEncryptionEncValuesSupported) {
        this.userInfoEncryptionEncValuesSupported = userInfoEncryptionEncValuesSupported;
    }

    public List<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    public void setIdTokenSigningAlgValuesSupported(List<String> idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
    }

    public List<String> getIdTokenEncryptionAlgValuesSupported() {
        return idTokenEncryptionAlgValuesSupported;
    }

    public void setIdTokenEncryptionAlgValuesSupported(List<String> idTokenEncryptionAlgValuesSupported) {
        this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
    }

    public List<String> getIdTokenEncryptionEncValuesSupported() {
        return idTokenEncryptionEncValuesSupported;
    }

    public void setIdTokenEncryptionEncValuesSupported(List<String> idTokenEncryptionEncValuesSupported) {
        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
    }

    public List<String> getRequestObjectSigningAlgValuesSupported() {
        return requestObjectSigningAlgValuesSupported;
    }

    public void setRequestObjectSigningAlgValuesSupported(List<String> requestObjectSigningAlgValuesSupported) {
        this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
    }

    public List<String> getRequestObjectEncryptionAlgValuesSupported() {
        return requestObjectEncryptionAlgValuesSupported;
    }

    public void setRequestObjectEncryptionAlgValuesSupported(List<String> requestObjectEncryptionAlgValuesSupported) {
        this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
    }

    public List<String> getRequestObjectEncryptionEncValuesSupported() {
        return requestObjectEncryptionEncValuesSupported;
    }

    public void setRequestObjectEncryptionEncValuesSupported(List<String> requestObjectEncryptionEncValuesSupported) {
        this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
    }

    public List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public void setTokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    public List<String> getTokenEndpointAuthSigningAlgValuesSupported() {
        return tokenEndpointAuthSigningAlgValuesSupported;
    }

    public void setTokenEndpointAuthSigningAlgValuesSupported(List<String> tokenEndpointAuthSigningAlgValuesSupported) {
        this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
    }

    public List<String> getDynamicRegistrationCustomAttributes() {
        return dynamicRegistrationCustomAttributes;
    }

    public void setDynamicRegistrationCustomAttributes(List<String> p_dynamicRegistrationCustomAttributes) {
        dynamicRegistrationCustomAttributes = p_dynamicRegistrationCustomAttributes;
    }

    public List<String> getDisplayValuesSupported() {
        return displayValuesSupported;
    }

    public void setDisplayValuesSupported(List<String> displayValuesSupported) {
        this.displayValuesSupported = displayValuesSupported;
    }

    public List<String> getClaimTypesSupported() {
        return claimTypesSupported;
    }

    public void setClaimTypesSupported(List<String> claimTypesSupported) {
        this.claimTypesSupported = claimTypesSupported;
    }

    public String getServiceDocumentation() {
        return serviceDocumentation;
    }

    public void setServiceDocumentation(String serviceDocumentation) {
        this.serviceDocumentation = serviceDocumentation;
    }

    public List<String> getClaimsLocalesSupported() {
        return claimsLocalesSupported;
    }

    public void setClaimsLocalesSupported(List<String> claimsLocalesSupported) {
        this.claimsLocalesSupported = claimsLocalesSupported;
    }

    public List<String> getUiLocalesSupported() {
        return uiLocalesSupported;
    }

    public void setUiLocalesSupported(List<String> uiLocalesSupported) {
        this.uiLocalesSupported = uiLocalesSupported;
    }

    public Boolean getClaimsParameterSupported() {
        return claimsParameterSupported;
    }

    public void setClaimsParameterSupported(Boolean claimsParameterSupported) {
        this.claimsParameterSupported = claimsParameterSupported;
    }

    public Boolean getRequestParameterSupported() {
        return requestParameterSupported;
    }

    public void setRequestParameterSupported(Boolean requestParameterSupported) {
        this.requestParameterSupported = requestParameterSupported;
    }

    public Boolean getRequestUriParameterSupported() {
        return requestUriParameterSupported;
    }

    public void setRequestUriParameterSupported(Boolean requestUriParameterSupported) {
        this.requestUriParameterSupported = requestUriParameterSupported;
    }

    public Boolean getRequireRequestUriRegistration() {
        return requireRequestUriRegistration;
    }

    public void setRequireRequestUriRegistration(Boolean requireRequestUriRegistration) {
        this.requireRequestUriRegistration = requireRequestUriRegistration;
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

    public int getAuthorizationCodeLifetime() {
        return authorizationCodeLifetime;
    }

    public void setAuthorizationCodeLifetime(int authorizationCodeLifetime) {
        this.authorizationCodeLifetime = authorizationCodeLifetime;
    }

    public int getRefreshTokenLifetime() {
        return refreshTokenLifetime;
    }

    public void setRefreshTokenLifetime(int refreshTokenLifetime) {
        this.refreshTokenLifetime = refreshTokenLifetime;
    }

    public int getIdTokenLifetime() {
        return idTokenLifetime;
    }

    public void setIdTokenLifetime(int idTokenLifetime) {
        this.idTokenLifetime = idTokenLifetime;
    }

    public int getShortLivedAccessTokenLifetime() {
        return shortLivedAccessTokenLifetime;
    }

    public void setShortLivedAccessTokenLifetime(int shortLivedAccessTokenLifetime) {
        this.shortLivedAccessTokenLifetime = shortLivedAccessTokenLifetime;
    }

    public int getLongLivedAccessTokenLifetime() {
        return longLivedAccessTokenLifetime;
    }

    public void setLongLivedAccessTokenLifetime(int longLivedAccessTokenLifetime) {
        this.longLivedAccessTokenLifetime = longLivedAccessTokenLifetime;
    }

    public int getUmaRequesterPermissionTokenLifetime() {
        return umaRequesterPermissionTokenLifetime;
    }

    public void setUmaRequesterPermissionTokenLifetime(int umaRequesterPermissionTokenLifetime) {
        this.umaRequesterPermissionTokenLifetime = umaRequesterPermissionTokenLifetime;
    }

    public int getCleanServiceInterval() {
        return cleanServiceInterval;
    }

    public void setCleanServiceInterval(int p_cleanServiceInterval) {
        cleanServiceInterval = p_cleanServiceInterval;
    }

    public Boolean getKeyRegenerationEnabled() {
        return keyRegenerationEnabled;
    }

    public void setKeyRegenerationEnabled(Boolean keyRegenerationEnabled) {
        this.keyRegenerationEnabled = keyRegenerationEnabled;
    }

    public int getKeyRegenerationInterval() {
        return keyRegenerationInterval;
    }

    public void setKeyRegenerationInterval(int keyRegenerationInterval) {
        this.keyRegenerationInterval = keyRegenerationInterval;
    }

    public String getDefaultSignatureAlgorithm() {
        return defaultSignatureAlgorithm;
    }

    public void setDefaultSignatureAlgorithm(String defaultSignatureAlgorithm) {
        this.defaultSignatureAlgorithm = defaultSignatureAlgorithm;
    }

    public String getOxOpenIdConnectVersion() {
        return oxOpenIdConnectVersion;
    }

    public void setOxOpenIdConnectVersion(String oxOpenIdConnectVersion) {
        this.oxOpenIdConnectVersion = oxOpenIdConnectVersion;
    }

    public String getOrganizationInum() {
        return organizationInum;
    }

    public void setOrganizationInum(String organizationInum) {
        this.organizationInum = organizationInum;
    }

    public String getOxId() {
        return oxId;
    }

    public void setOxId(String oxId) {
        this.oxId = oxId;
    }

    public Boolean getDynamicRegistrationEnabled() {
        return dynamicRegistrationEnabled;
    }

    public void setDynamicRegistrationEnabled(Boolean dynamicRegistrationEnabled) {
        this.dynamicRegistrationEnabled = dynamicRegistrationEnabled;
    }

    public int getDynamicRegistrationExpirationTime() {
        return dynamicRegistrationExpirationTime;
    }

    public void setDynamicRegistrationExpirationTime(int dynamicRegistrationExpirationTime) {
        this.dynamicRegistrationExpirationTime = dynamicRegistrationExpirationTime;
    }

    public Boolean getDynamicRegistrationPersistClientAuthorizations() {
        return dynamicRegistrationPersistClientAuthorizations;
    }

    public void setDynamicRegistrationPersistClientAuthorizations(Boolean dynamicRegistrationPersistClientAuthorizations) {
        this.dynamicRegistrationPersistClientAuthorizations = dynamicRegistrationPersistClientAuthorizations;
    }

    public Boolean getTrustedClientEnabled() {
        return trustedClientEnabled;
    }

    public void setTrustedClientEnabled(Boolean trustedClientEnabled) {
        this.trustedClientEnabled = trustedClientEnabled;
    }

    public Boolean getDynamicRegistrationScopesParamEnabled() {
        return dynamicRegistrationScopesParamEnabled;
    }

    public void setDynamicRegistrationScopesParamEnabled(Boolean dynamicRegistrationScopesParamEnabled) {
        this.dynamicRegistrationScopesParamEnabled = dynamicRegistrationScopesParamEnabled;
    }

    public String getDynamicRegistrationCustomObjectClass() {
        return dynamicRegistrationCustomObjectClass;
    }

    public void setDynamicRegistrationCustomObjectClass(String p_dynamicRegistrationCustomObjectClass) {
        dynamicRegistrationCustomObjectClass = p_dynamicRegistrationCustomObjectClass;
    }

    public Boolean getAuthenticationFiltersEnabled() {
        return authenticationFiltersEnabled;
    }

    public void setAuthenticationFiltersEnabled(Boolean authenticationFiltersEnabled) {
        this.authenticationFiltersEnabled = authenticationFiltersEnabled;
    }

    public Boolean getClientAuthenticationFiltersEnabled() {
        return clientAuthenticationFiltersEnabled;
    }

    public void setClientAuthenticationFiltersEnabled(Boolean p_clientAuthenticationFiltersEnabled) {
        clientAuthenticationFiltersEnabled = p_clientAuthenticationFiltersEnabled;
    }

    public List<AuthenticationFilter> getAuthenticationFilters() {
        if (authenticationFilters == null) {
            authenticationFilters = new ArrayList<AuthenticationFilter>();
        }

        return authenticationFilters;
    }

    public List<ClientAuthenticationFilter> getClientAuthenticationFilters() {
        if (clientAuthenticationFilters == null) {
            clientAuthenticationFilters = new ArrayList<ClientAuthenticationFilter>();
        }

        return clientAuthenticationFilters;
    }

    public List<CorsConfigurationFilter> getCorsConfigurationFilters() {
        if (corsConfigurationFilters == null) {
            corsConfigurationFilters = new ArrayList<CorsConfigurationFilter>();
        }

        return corsConfigurationFilters;
    }

    public String getApplianceInum() {
        return applianceInum;
    }

    public void setApplianceInum(String applianceInum) {
        this.applianceInum = applianceInum;
    }

    public int getSessionIdUnusedLifetime() {
        return sessionIdUnusedLifetime;
    }

    public void setSessionIdUnusedLifetime(int p_sessionIdUnusedLifetime) {
        sessionIdUnusedLifetime = p_sessionIdUnusedLifetime;
    }

    public int getSessionIdUnauthenticatedUnusedLifetime() {
        return sessionIdUnauthenticatedUnusedLifetime;
    }

    public void setSessionIdUnauthenticatedUnusedLifetime(int sessionIdUnauthenticatedUnusedLifetime) {
        this.sessionIdUnauthenticatedUnusedLifetime = sessionIdUnauthenticatedUnusedLifetime;
    }

    public Boolean getSessionIdPersistOnPromptNone() {
        return sessionIdPersistOnPromptNone;
    }

    public void setSessionIdPersistOnPromptNone(Boolean sessionIdPersistOnPromptNone) {
        this.sessionIdPersistOnPromptNone = sessionIdPersistOnPromptNone;
    }

    public Boolean getSessionIdEnabled() {
        return sessionIdEnabled;
    }

    public void setSessionIdEnabled(Boolean p_sessionIdEnabled) {
        sessionIdEnabled = p_sessionIdEnabled;
    }

    public Integer getSessionIdLifetime() {
        return sessionIdLifetime;
    }

    public void setSessionIdLifetime(Integer sessionIdLifetime) {
        this.sessionIdLifetime = sessionIdLifetime;
    }

    public int getConfigurationUpdateInterval() {
        return configurationUpdateInterval;
    }

    public void setConfigurationUpdateInterval(int p_configurationUpdateInterval) {
        configurationUpdateInterval = p_configurationUpdateInterval;
    }

    public String getJsLocation() {
        return jsLocation;
    }

    public void setJsLocation(String jsLocation) {
        this.jsLocation = jsLocation;
    }

    public String getCssLocation() {
        return cssLocation;
    }

    public void setCssLocation(String cssLocation) {
        this.cssLocation = cssLocation;
    }

    public String getImgLocation() {
        return imgLocation;
    }

    public void setImgLocation(String imgLocation) {
        this.imgLocation = imgLocation;
    }

    public int getMetricReporterInterval() {
        return metricReporterInterval;
    }

    public void setMetricReporterInterval(int metricReporterInterval) {
        this.metricReporterInterval = metricReporterInterval;
    }

    public int getMetricReporterKeepDataDays() {
        return metricReporterKeepDataDays;
    }

    public void setMetricReporterKeepDataDays(int metricReporterKeepDataDays) {
        this.metricReporterKeepDataDays = metricReporterKeepDataDays;
    }

    public String getPairwiseIdType() {
        return pairwiseIdType;
    }

    public void setPairwiseIdType(String pairwiseIdType) {
        this.pairwiseIdType = pairwiseIdType;
    }

    public String getPairwiseCalculationKey() {
        return pairwiseCalculationKey;
    }

    public void setPairwiseCalculationKey(String pairwiseCalculationKey) {
        this.pairwiseCalculationKey = pairwiseCalculationKey;
    }

    public String getPairwiseCalculationSalt() {
        return pairwiseCalculationSalt;
    }

    public void setPairwiseCalculationSalt(String pairwiseCalculationSalt) {
        this.pairwiseCalculationSalt = pairwiseCalculationSalt;
    }

    public WebKeyStorage getWebKeysStorage() {
        return webKeysStorage;
    }

    public void setWebKeysStorage(WebKeyStorage webKeysStorage) {
        this.webKeysStorage = webKeysStorage;
    }

    public String getDnName() {
        return dnName;
    }

    public void setDnName(String dnName) {
        this.dnName = dnName;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public String getKeyStoreSecret() {
        return keyStoreSecret;
    }

    public void setKeyStoreSecret(String keyStoreSecret) {
        this.keyStoreSecret = keyStoreSecret;
    }

    public String getOxElevenGenerateKeyEndpoint() {
        return oxElevenGenerateKeyEndpoint;
    }

    public void setOxElevenGenerateKeyEndpoint(String oxElevenGenerateKeyEndpoint) {
        this.oxElevenGenerateKeyEndpoint = oxElevenGenerateKeyEndpoint;
    }

    public String getOxElevenSignEndpoint() {
        return oxElevenSignEndpoint;
    }

    public void setOxElevenSignEndpoint(String oxElevenSignEndpoint) {
        this.oxElevenSignEndpoint = oxElevenSignEndpoint;
    }

    public String getOxElevenVerifySignatureEndpoint() {
        return oxElevenVerifySignatureEndpoint;
    }

    public void setOxElevenVerifySignatureEndpoint(String oxElevenVerifySignatureEndpoint) {
        this.oxElevenVerifySignatureEndpoint = oxElevenVerifySignatureEndpoint;
    }

    public String getOxElevenDeleteKeyEndpoint() {
        return oxElevenDeleteKeyEndpoint;
    }

    public void setOxElevenDeleteKeyEndpoint(String oxElevenDeleteKeyEndpoint) {
        this.oxElevenDeleteKeyEndpoint = oxElevenDeleteKeyEndpoint;
    }

    public Boolean getEndSessionWithAccessToken() {
        return endSessionWithAccessToken;
    }

    public void setEndSessionWithAccessToken(Boolean endSessionWithAccessToken) {
        this.endSessionWithAccessToken = endSessionWithAccessToken;
    }

    public Boolean getEnabledOAuthAuditLogging() {
        return enabledOAuthAuditLogging;
    }

    public void setEnabledOAuthAuditLogging(Boolean enabledOAuthAuditLogging) {
        this.enabledOAuthAuditLogging = enabledOAuthAuditLogging;
    }

    public Set<String> getJmsBrokerURISet() {
        return jmsBrokerURISet;
    }

    public void setJmsBrokerURISet(Set<String> jmsBrokerURISet) {
        this.jmsBrokerURISet = jmsBrokerURISet;
    }

    public String getJmsUserName() {
        return jmsUserName;
    }

    public void setJmsUserName(String jmsUserName) {
        this.jmsUserName = jmsUserName;
    }

    public String getJmsPassword() {
        return jmsPassword;
    }

    public void setJmsPassword(String jmsPassword) {
        this.jmsPassword = jmsPassword;
    }

    public List<String> getClientWhiteList() {
        return clientWhiteList;
    }

    public void setClientWhiteList(List<String> clientWhiteList) {
        this.clientWhiteList = clientWhiteList;
    }

    public List<String> getClientBlackList() {
        return clientBlackList;
    }

    public void setClientBlackList(List<String> clientBlackList) {
        this.clientBlackList = clientBlackList;
    }

    public Boolean getLegacyIdTokenClaims() {
        return legacyIdTokenClaims;
    }

    public void setLegacyIdTokenClaims(Boolean legacyIdTokenClaims) {
        this.legacyIdTokenClaims = legacyIdTokenClaims;
    }

    public Boolean getCustomHeadersWithAuthorizationResponse() {
        if (customHeadersWithAuthorizationResponse == null) {
            return false;
        }

        return customHeadersWithAuthorizationResponse;
    }

    public void setCustomHeadersWithAuthorizationResponse(Boolean customHeadersWithAuthorizationResponse) {
        this.customHeadersWithAuthorizationResponse = customHeadersWithAuthorizationResponse;
    }

    public Boolean getUpdateUserLastLogonTime() {
        return updateUserLastLogonTime != null ? updateUserLastLogonTime : false;
    }

    public void setUpdateUserLastLogonTime(Boolean updateUserLastLogonTime) {
        this.updateUserLastLogonTime = updateUserLastLogonTime;
    }

    public Boolean getUpdateClientAccessTime() {
        return updateClientAccessTime != null ? updateClientAccessTime : false;
    }

    public void setUpdateClientAccessTime(Boolean updateClientAccessTime) {
        this.updateClientAccessTime = updateClientAccessTime;
    }

    public String getLoggingLevel() {
        return loggingLevel;
    }

    public void setLoggingLevel(String loggingLevel) {
        this.loggingLevel = loggingLevel;
    }

}