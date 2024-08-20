/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.registration;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.model.common.GrantType;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.common.SubjectType;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.register.ApplicationType;
import org.gluu.oxauth.model.register.RegisterErrorResponseType;
import org.gluu.oxauth.model.util.Pair;
import org.gluu.oxauth.model.util.URLPatternList;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.util.ServerUtil;
import org.json.JSONArray;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.apache.commons.lang.BooleanUtils.isTrue;

/**
 * Validates the parameters received for the register web service.
 *
 * @author Javier Rojas Blum
 * @version October 22, 2019
 */
@ApplicationScoped
public class RegisterParamsValidator {

    @Inject
    private Logger log;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    private static final String LOCALHOST = "localhost";
    private static final String LOOPBACK = "127.0.0.1";

    /**
     * Validates the parameters for a register request.
     *
     * @param applicationType The Application Type: native or web.
     * @param subjectType     The subject_type requested for responses to this Client.
     * @param grantTypes      Grant Types that the Client is declaring that it will restrict itself to using.
     * @param redirectUris    Space-separated list of redirect URIs.
     * @return Whether the parameters of client register is valid or not.
     */
    public Pair<Boolean, String> validateParamsClientRegister(
            ApplicationType applicationType, SubjectType subjectType,
            List<GrantType> grantTypes, List<ResponseType> responseTypes,
            List<String> redirectUris) {
        if (applicationType == null) {
            return new Pair<>(false, "application_type is not valid.");
        }

        if (grantTypes != null &&
                (grantTypes.contains(GrantType.AUTHORIZATION_CODE) || grantTypes.contains(GrantType.IMPLICIT)
                || (responseTypes.contains(ResponseType.CODE) && !grantTypes.contains(GrantType.DEVICE_CODE))
                || responseTypes.contains(ResponseType.TOKEN) || responseTypes.contains(ResponseType.ID_TOKEN))) {
            if (redirectUris == null || redirectUris.isEmpty()) {
                return new Pair<>(false, "Redirect uris are empty.");
            }
        }

        if (subjectType == null || !appConfiguration.getSubjectTypesSupported().contains(subjectType.toString())) {
            log.debug("Parameter subject_type is not valid.");
            return new Pair<>(false, "Parameter subject_type is not valid.");
        }

        return new Pair<>(true, "");
    }

    /**
     * Validates all algorithms received for a register client request. It throws a WebApplicationException
     * whether a validation doesn't pass.
     *
     * @param registerRequest Object containing all parameters received to register a client.
     */
    public void validateAlgorithms( RegisterRequest registerRequest ) {
        if ( registerRequest.getIdTokenSignedResponseAlg() != null
                && registerRequest.getIdTokenSignedResponseAlg() != SignatureAlgorithm.NONE &&
                ! appConfiguration.getIdTokenSigningAlgValuesSupported().contains(
                        registerRequest.getIdTokenSignedResponseAlg().toString()) ) {
            log.debug("Parameter id_token_signed_response_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter id_token_signed_response_alg is not valid.");
        }

        if ( registerRequest.getIdTokenEncryptedResponseAlg() != null &&
                ! appConfiguration.getIdTokenEncryptionAlgValuesSupported().contains(
                        registerRequest.getIdTokenEncryptedResponseAlg().toString()) ) {
            log.debug("Parameter id_token_encrypted_response_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter id_token_encrypted_response_alg is not valid.");
        }

        if ( registerRequest.getIdTokenEncryptedResponseEnc() != null &&
                ! appConfiguration.getIdTokenEncryptionEncValuesSupported().contains(
                        registerRequest.getIdTokenEncryptedResponseEnc().toString()) ) {
            log.debug("Parameter id_token_encrypted_response_enc is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter id_token_encrypted_response_enc is not valid.");
        }

        if ( registerRequest.getUserInfoSignedResponseAlg() != null &&
                ! appConfiguration.getUserInfoSigningAlgValuesSupported().contains(
                        registerRequest.getUserInfoSignedResponseAlg().toString()) ) {
            log.debug("Parameter userinfo_signed_response_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter userinfo_signed_response_alg is not valid.");
        }

        if ( registerRequest.getUserInfoEncryptedResponseAlg() != null &&
                ! appConfiguration.getUserInfoEncryptionAlgValuesSupported().contains(
                        registerRequest.getUserInfoEncryptedResponseAlg().toString()) ) {
            log.debug("Parameter userinfo_encrypted_response_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter userinfo_encrypted_response_alg is not valid.");
        }

        if ( registerRequest.getUserInfoEncryptedResponseEnc() != null &&
                ! appConfiguration.getUserInfoEncryptionEncValuesSupported().contains(
                        registerRequest.getUserInfoEncryptedResponseEnc().toString()) ) {
            log.debug("Parameter userinfo_encrypted_response_enc is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter userinfo_encrypted_response_enc is not valid.");
        }

        if ( registerRequest.getRequestObjectSigningAlg() != null &&
                ! appConfiguration.getRequestObjectSigningAlgValuesSupported().contains(
                        registerRequest.getRequestObjectSigningAlg().toString()) ) {
            log.debug("Parameter request_object_signing_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter request_object_signing_alg is not valid.");
        }

        if ( registerRequest.getRequestObjectEncryptionAlg() != null &&
                ! appConfiguration.getRequestObjectEncryptionAlgValuesSupported().contains(
                        registerRequest.getRequestObjectEncryptionAlg().toString()) ) {
            log.debug("Parameter request_object_encryption_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter request_object_encryption_alg is not valid.");
        }

        if ( registerRequest.getRequestObjectEncryptionEnc() != null &&
                ! appConfiguration.getRequestObjectEncryptionEncValuesSupported().contains(
                        registerRequest.getRequestObjectEncryptionEnc().toString()) ) {
            log.debug("Parameter request_object_encryption_enc is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter request_object_encryption_enc is not valid.");
        }

        if ( registerRequest.getTokenEndpointAuthMethod() != null &&
                ! appConfiguration.getTokenEndpointAuthMethodsSupported().contains(
                        registerRequest.getTokenEndpointAuthMethod().toString()) ) {
            log.debug("Parameter token_endpoint_auth_method is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter token_endpoint_auth_method is not valid.");
        }

        if ( registerRequest.getTokenEndpointAuthSigningAlg() != null &&
                ! appConfiguration.getTokenEndpointAuthSigningAlgValuesSupported().contains(
                        registerRequest.getTokenEndpointAuthSigningAlg().toString()) ) {
            log.debug("Parameter token_endpoint_auth_signing_alg is not valid.");
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST,
                    RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Parameter token_endpoint_auth_signing_alg is not valid.");
        }
    }

    /**
     * Validates the parameters for a client read request.
     *
     * @param clientId    Unique Client identifier.
     * @param accessToken Access Token obtained out of band to authorize the registrant.
     * @return Whether the parameters of client read is valid or not.
     */
    public boolean validateParamsClientRead(String clientId, String accessToken) {
        return StringUtils.isNotBlank(clientId) && StringUtils.isNotBlank(accessToken);
    }

    /**
     * @param grantTypes          Grant Types that the Client is declaring that it will restrict itself to using.
     * @param applicationType     The Application Type: native or web.
     * @param subjectType         Subject Type requested for responses to this Client.
     * @param redirectUris        Redirection URI values used by the Client.
     * @param sectorIdentifierUrl A HTTPS scheme URL to be used in calculating Pseudonymous Identifiers by the OP.
     *                            The URL contains a file with a single JSON array of redirect_uri values.
     * @return Whether the Redirect URI parameters are valid or not.
     */
    public boolean validateRedirectUris(List<GrantType> grantTypes, List<ResponseType> responseTypes,
                                        ApplicationType applicationType, SubjectType subjectType,
                                        List<String> redirectUris, String sectorIdentifierUrl) {
        boolean valid = true;
        Set<String> redirectUriHosts = new HashSet<String>();

        if (redirectUris != null && !redirectUris.isEmpty()) {
            for (String redirectUri : redirectUris) {
                if (redirectUri == null || redirectUri.contains("#")) {
                    valid = false;
                } else {
                    URI uri = null;
                    try {
                        uri = new URI(redirectUri);
                    } catch (URISyntaxException e) {
                        log.debug("Failed to parse redirect_uri: {}, error: {}", redirectUri, e.getMessage());
                        valid = false;
                        continue;
                    }
                    redirectUriHosts.add(uri.getHost());
                    switch (applicationType) {
                        case WEB:
                            if (HTTP.equalsIgnoreCase(uri.getScheme())) {
                                if (!LOCALHOST.equalsIgnoreCase(uri.getHost()) && !LOOPBACK.equalsIgnoreCase(uri.getHost())) {
                                    log.debug("Invalid protocol for redirect_uri: " +
                                            redirectUri +
                                            " (only https protocol is allowed for application_type=web or localhost/127.0.0.1 for http)");
                                    valid = false;
                                }
                            }
                            break;
                        case NATIVE:
                            // to conform "OAuth 2.0 for Native Apps" https://tools.ietf.org/html/draft-wdenniss-oauth-native-apps-00
                            // we allow registration with custom schema for native apps.
//                                if (!HTTP.equalsIgnoreCase(uri.getScheme())) {
//                                    valid = false;
//                                } else if (!LOCALHOST.equalsIgnoreCase(uri.getHost())) {
//                                    valid = false;
//                                }
                            break;
                    }
                }
            }
        } else if (!grantTypes.contains(GrantType.AUTHORIZATION_CODE) && !grantTypes.contains(GrantType.IMPLICIT) &&
                (!responseTypes.contains(ResponseType.CODE) || grantTypes.contains(GrantType.DEVICE_CODE))
                && !responseTypes.contains(ResponseType.TOKEN) && !responseTypes.contains(ResponseType.ID_TOKEN)) {
            // It is valid for grant types: password, client_credentials, urn:ietf:params:oauth:grant-type:uma-ticket and urn:openid:params:grant-type:ciba
            valid = true;
        } else {
            valid = false;
        }


        /*
         * Providers that use pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value
         * provided in the Subject Identifier calculation for pairwise identifiers.
         *
         * If the Client has not provided a value for sector_identifier_uri in Dynamic Client Registration,
         * the Sector Identifier used for pairwise identifier calculation is the host component of the
         * registered redirect_uri.
         *
         * If there are multiple hostnames in the registered redirect_uris, the Client MUST register a
         * sector_identifier_uri.
         */
        if (subjectType != null && subjectType.equals(SubjectType.PAIRWISE) && StringUtils.isBlank(sectorIdentifierUrl)) {
            if (redirectUriHosts.size() > 1) {
                valid = false;
            }
        }

        // Validate Sector Identifier URL
        boolean noRedirectUriInSectorIdentifierUri = false;
        if (valid && StringUtils.isNotBlank(sectorIdentifierUrl)) {
            try {
                URI uri = new URI(sectorIdentifierUrl);
                if (!HTTPS.equalsIgnoreCase(uri.getScheme())) {
                    valid = false;
                }

                javax.ws.rs.client.Client clientRequest = ClientBuilder.newClient();
        		String entity = null;
        		try {
        			Response clientResponse = clientRequest.target(sectorIdentifierUrl).request().buildGet().invoke();
	                int status = clientResponse.getStatus();
	
	                if (status == 200) {
	                    entity = clientResponse.readEntity(String.class);
	
	                    JSONArray sectorIdentifierJsonArray = new JSONArray(entity);
	                    valid = Util.asList(sectorIdentifierJsonArray).containsAll(redirectUris);
	                }
        		} finally {
        			clientRequest.close();
        		}
            } catch (Exception e) {
                log.debug(e.getMessage(), e);
                valid = false;
            } finally {
                if (!valid) {
                    noRedirectUriInSectorIdentifierUri = true;
                }
            }
        }

        // Validate Redirect Uris checking the white list and black list
        if (valid || isTrue(appConfiguration.getAllowWildcardRedirectUri())) {
            valid = checkWhiteListRedirectUris(redirectUris) && checkBlackListRedirectUris(redirectUris);
        }

        if (noRedirectUriInSectorIdentifierUri) {
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Failed to validate redirect uris. No redirect_uri in sector_identifier_uri content.");
        }

        return valid;
    }

    public boolean validateInitiateLoginUri(String initiateLoginUri) {
        boolean valid = false;

        try {
            URI uri = new URI(initiateLoginUri);
            if (HTTPS.equalsIgnoreCase(uri.getScheme())) {
                valid = true;
            }
        } catch (URISyntaxException e) {
            log.debug(e.getMessage(), e);
            valid = false;
        }

        return valid;
    }

    /**
     * All the Redirect Uris must match to return true.
     */
    private boolean checkWhiteListRedirectUris(List<String> redirectUris) {
        boolean valid = true;
        List<String> whiteList = appConfiguration.getClientWhiteList();
        boolean wildcardSupported = isTrue(appConfiguration.getAllowWildcardRedirectUri());
        URLPatternList urlPatternList = new URLPatternList(whiteList, wildcardSupported);

        for (String redirectUri : redirectUris) {
            valid &= urlPatternList.isUrlListed(redirectUri);
        }

        return valid;
    }

    /**
     * None of the Redirect Uris must match to return true.
     */
    private boolean checkBlackListRedirectUris(List<String> redirectUris) {
        boolean valid = true;
        List<String> blackList = appConfiguration.getClientBlackList();
        boolean wildcardSupported = isTrue(appConfiguration.getAllowWildcardRedirectUri());
        URLPatternList urlPatternList = new URLPatternList(blackList, wildcardSupported);

        for (String redirectUri : redirectUris) {
            valid &= !urlPatternList.isUrlListed(redirectUri);
        }

        return valid;
    }

    public void validateLogoutUri(List<String> logoutUris, List<String> redirectUris, ErrorResponseFactory errorResponseFactory) {
        if (logoutUris == null || logoutUris.isEmpty()) { // logout uri is optional so null or empty list is valid
            return;
        }
        for (String logoutUri : logoutUris) {
            validateLogoutUri(logoutUri, redirectUris, errorResponseFactory);
        }
    }

    public void validateLogoutUri(String logoutUri, List<String> redirectUris, ErrorResponseFactory errorResponseFactory) {
        if (Util.isNullOrEmpty(logoutUri)) { // logout uri is optional so null or empty string is valid
            return;
        }

        // preconditions
        if (redirectUris == null || redirectUris.isEmpty()) {
            log.debug("Preconditions of logout uri validation are failed.");
            throwInvalidLogoutUri(errorResponseFactory);
            return;
        }

        try {
            Set<String> redirectUriHosts = collectUriHosts(redirectUris);

            URI uri = new URI(logoutUri);

            if (!redirectUriHosts.contains(uri.getHost())) {
                log.debug("logout uri host is not within redirect_uris, logout_uri: {}, redirect_uris: {}", logoutUri, redirectUris);
                throwInvalidLogoutUri(errorResponseFactory);
                return;
            }

            if (!HTTPS.equalsIgnoreCase(uri.getScheme())) {
                log.debug("logout uri schema is not https, logout_uri: {}", logoutUri);
                throwInvalidLogoutUri(errorResponseFactory);
            }
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
            throwInvalidLogoutUri(errorResponseFactory);
        }
    }

    private void throwInvalidLogoutUri(ErrorResponseFactory errorResponseFactory) throws WebApplicationException {
        throw new WebApplicationException(
                Response.status(Response.Status.BAD_REQUEST.getStatusCode()).
                        type(MediaType.APPLICATION_JSON_TYPE).
                        entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_LOGOUT_URI, "Failed to valide logout uri.")).
                        cacheControl(ServerUtil.cacheControl(true, false)).
                        header("Pragma", "no-cache").
                        build());
    }

    private static Set<String> collectUriHosts(List<String> uriList) throws URISyntaxException {
        Set<String> hosts = new HashSet<String>();

        for (String redirectUri : uriList) {
            URI uri = new URI(redirectUri);
            hosts.add(uri.getHost());
        }
        return hosts;
    }

    /**
     * Check if exists a Password Grant Type in the list of Grant Types.
     * @param grantTypes List of Grant Types.
     * @return True if Password Grant Type exists in the list, otherwise false
     */
    public boolean checkIfThereIsPasswordGrantType(List<GrantType> grantTypes) {
        if (grantTypes != null)
            return grantTypes.stream().anyMatch(grantType -> grantType == GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS);
        return false;
    }

}