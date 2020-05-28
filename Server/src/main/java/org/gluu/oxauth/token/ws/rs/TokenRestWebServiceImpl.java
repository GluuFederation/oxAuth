/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.token.ws.rs;

import com.google.common.base.Function;
import com.google.common.base.Strings;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.audit.ApplicationAuditLogger;
import org.gluu.oxauth.model.audit.Action;
import org.gluu.oxauth.model.audit.OAuth2AuditLog;
import org.gluu.oxauth.model.authorize.CodeVerifier;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.config.Constants;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.binding.TokenBindingMessage;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionClient;
import org.gluu.oxauth.model.token.JsonWebResponse;
import org.gluu.oxauth.model.token.JwrService;
import org.gluu.oxauth.model.token.TokenErrorResponseType;
import org.gluu.oxauth.model.token.TokenParamsValidator;
import org.gluu.oxauth.security.Identity;
import org.gluu.oxauth.service.AttributeService;
import org.gluu.oxauth.service.AuthenticationFilterService;
import org.gluu.oxauth.service.AuthenticationService;
import org.gluu.oxauth.service.GrantService;
import org.gluu.oxauth.service.SessionIdService;
import org.gluu.oxauth.service.UserService;
import org.gluu.oxauth.service.common.*;
import org.gluu.oxauth.service.external.ExternalResourceOwnerPasswordCredentialsService;
import org.gluu.oxauth.service.external.context.ExternalResourceOwnerPasswordCredentialsContext;
import org.gluu.oxauth.uma.service.UmaTokenService;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.persist.exception.AuthenticationException;
import org.gluu.util.OxConstants;
import org.gluu.util.StringHelper;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.SecurityContext;
import java.util.Arrays;
import java.util.Date;

/**
 * Provides interface for token REST web services
 *
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version May 5, 2020
 */
@Path("/")
public class TokenRestWebServiceImpl implements TokenRestWebService {

    @Inject
    private Logger log;

    @Inject
    private Identity identity;

    @Inject
    private ApplicationAuditLogger applicationAuditLogger;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Inject
    private UserService userService;

    @Inject
    private GrantService grantService;

    @Inject
    private AuthenticationFilterService authenticationFilterService;

    @Inject
    private AuthenticationService authenticationService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private UmaTokenService umaTokenService;

    @Inject
    private ExternalResourceOwnerPasswordCredentialsService externalResourceOwnerPasswordCredentialsService;

    @Inject
    private AttributeService attributeService;

    @Inject
    private SessionIdService sessionIdService;

    @Override
    public Response requestAccessToken(String grantType, String code,
                                       String redirectUri, String username, String password, String scope,
                                       String assertion, String refreshToken,
                                       String clientId, String clientSecret, String codeVerifier,
                                       String ticket, String claimToken, String claimTokenFormat, String pctCode,
                                       String rptCode, String authReqId,
                                       HttpServletRequest request, HttpServletResponse response, SecurityContext sec) {
        log.debug(
                "Attempting to request access token: grantType = {}, code = {}, redirectUri = {}, username = {}, refreshToken = {}, " +
                        "clientId = {}, ExtraParams = {}, isSecure = {}, codeVerifier = {}, ticket = {}",
                grantType, code, redirectUri, username, refreshToken, clientId, request.getParameterMap(),
                sec.isSecure(), codeVerifier, ticket);

        boolean isUma = StringUtils.isNotBlank(ticket);
        if (isUma) {
            return umaTokenService.requestRpt(grantType, ticket, claimToken, claimTokenFormat, pctCode, rptCode, scope, request);
        }

        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(request), Action.TOKEN_REQUEST);
        oAuth2AuditLog.setClientId(clientId);
        oAuth2AuditLog.setUsername(username);
        oAuth2AuditLog.setScope(scope);

        String tokenBindingHeader = request.getHeader("Sec-Token-Binding");

        scope = ServerUtil.urlDecode(scope); // it may be encoded in uma case
        ResponseBuilder builder = Response.ok();

        try {
            log.debug("Starting to validate request parameters");
            if (!TokenParamsValidator.validateParams(grantType, code, redirectUri, username, password,
                    scope, assertion, refreshToken)) {
                log.trace("Failed to validate request parameters");
                return response(error(400, TokenErrorResponseType.INVALID_REQUEST, "Failed to validate request parameters"), oAuth2AuditLog);
            }

            GrantType gt = GrantType.fromString(grantType);
            log.debug("Grant type: '{}'", gt);

            SessionClient sessionClient = identity.getSessionClient();
            Client client = null;
            if (sessionClient != null) {
                client = sessionClient.getClient();
                log.debug("Get sessionClient: '{}'", sessionClient);
            }

            if (client == null) {
                return response(error(401, TokenErrorResponseType.INVALID_GRANT, "Unable to find client."), oAuth2AuditLog);
            }

            log.debug("Get client from session: '{}'", client.getClientId());
            if (client.isDisabled()) {
                return response(error(Response.Status.FORBIDDEN.getStatusCode(), TokenErrorResponseType.DISABLED_CLIENT, "Client is disabled."), oAuth2AuditLog);
            }

            final Function<JsonWebResponse, Void> idTokenTokingBindingPreprocessing = TokenBindingMessage.createIdTokenTokingBindingPreprocessing(
                    tokenBindingHeader, client.getIdTokenTokenBindingCnf()); // for all except authorization code grant
            final SessionId sessionIdObj = sessionIdService.getSessionId(request);
            final Function<JsonWebResponse, Void> idTokenPreProcessing = JwrService.wrapWithSidFunction(idTokenTokingBindingPreprocessing, sessionIdObj != null ? sessionIdObj.getId() : null);


            if (gt == GrantType.AUTHORIZATION_CODE) {
                if (!TokenParamsValidator.validateGrantType(gt, client.getGrantTypes(), appConfiguration.getGrantTypesSupported())) {
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "Grant types are invalid."), oAuth2AuditLog);
                }

                log.debug("Attempting to find authorizationCodeGrant by clientId: '{}', code: '{}'", client.getClientId(), code);
                final AuthorizationCodeGrant authorizationCodeGrant = authorizationGrantList.getAuthorizationCodeGrant(code);
                log.trace("AuthorizationCodeGrant : '{}'", authorizationCodeGrant);

                if (authorizationCodeGrant == null) {
                    log.debug("AuthorizationCodeGrant is empty by clientId: '{}', code: '{}'", client.getClientId(), code);
                    // if authorization code is not found then code was already used or wrong client provided = remove all grants with this auth code
                    grantService.removeAllByAuthorizationCode(code);
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "Unable to find grant object for given code."), oAuth2AuditLog);
                }

                if (!client.getClientId().equals(authorizationCodeGrant.getClientId())) {
                    log.debug("AuthorizationCodeGrant is found but belongs to another client. Grant's clientId: '{}', code: '{}'", authorizationCodeGrant.getClientId(), code);
                    // if authorization code is not found then code was already used or wrong client provided = remove all grants with this auth code
                    grantService.removeAllByAuthorizationCode(code);
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "Client mismatch."), oAuth2AuditLog);
                }

                validatePKCE(authorizationCodeGrant, codeVerifier, oAuth2AuditLog);

                authorizationCodeGrant.setIsCachedWithNoPersistence(false);
                authorizationCodeGrant.save();

                RefreshToken reToken = null;
                if (isRefreshTokenAllowed(client, authorizationCodeGrant)) {
                    reToken = authorizationCodeGrant.createRefreshToken();
                }

                if (scope != null && !scope.isEmpty()) {
                    scope = authorizationCodeGrant.checkScopesPolicy(scope);
                }

                AccessToken accToken = authorizationCodeGrant.createAccessToken(request.getHeader("X-ClientCert"), new ExecutionContext(request, response)); // create token after scopes are checked
                log.debug("Issuing access token: {}", accToken.getCode());

                IdToken idToken = null;
                if (authorizationCodeGrant.getScopes().contains("openid")) {
                    String nonce = authorizationCodeGrant.getNonce();
                    boolean includeIdTokenClaims = Boolean.TRUE.equals(
                            appConfiguration.getLegacyIdTokenClaims());
                    final String idTokenTokenBindingCnf = client.getIdTokenTokenBindingCnf();
                    Function<JsonWebResponse, Void> authorizationCodePreProcessing = jsonWebResponse -> {
                        if (StringUtils.isNotBlank(idTokenTokenBindingCnf) && StringUtils.isNotBlank(authorizationCodeGrant.getTokenBindingHash())) {
                            TokenBindingMessage.setCnfClaim(jsonWebResponse, authorizationCodeGrant.getTokenBindingHash(), idTokenTokenBindingCnf);
                        }
                        return null;
                    };

                    idToken = authorizationCodeGrant.createIdToken(
                            nonce, authorizationCodeGrant.getAuthorizationCode(), accToken, null, null,
                            authorizationCodeGrant, includeIdTokenClaims, JwrService.wrapWithSidFunction(authorizationCodePreProcessing, sessionIdObj != null ? sessionIdObj.getId() : null));
                }


                oAuth2AuditLog.updateOAuth2AuditLog(authorizationCodeGrant, true);

                grantService.removeByCode(authorizationCodeGrant.getAuthorizationCode().getCode());

                final String entity = getJSonResponse(accToken, accToken.getTokenType(), accToken.getExpiresIn(), reToken, scope, idToken);
                return response(Response.ok().entity(entity), oAuth2AuditLog);
            }

            if (gt == GrantType.REFRESH_TOKEN) {
                if (!TokenParamsValidator.validateGrantType(gt, client.getGrantTypes(), appConfiguration.getGrantTypesSupported())) {
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "grant_type is not present in client."), oAuth2AuditLog);
                }

                AuthorizationGrant authorizationGrant = authorizationGrantList.getAuthorizationGrantByRefreshToken(client.getClientId(), refreshToken);

                if (authorizationGrant == null) {
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "Unable to find grant object by refresh token or otherwise token type or client does not match."), oAuth2AuditLog);
                }

                // The authorization server MAY issue a new refresh token, in which case
                // the client MUST discard the old refresh token and replace it with the new refresh token.
                RefreshToken reToken = authorizationGrant.createRefreshToken();
                grantService.removeByCode(refreshToken);

                if (scope != null && !scope.isEmpty()) {
                    scope = authorizationGrant.checkScopesPolicy(scope);
                }

                AccessToken accToken = authorizationGrant.createAccessToken(request.getHeader("X-ClientCert"), new ExecutionContext(request, response)); // create token after scopes are checked

                IdToken idToken = null;
                if (appConfiguration.getOpenidScopeBackwardCompatibility() && authorizationGrant.getScopes().contains("openid")) {
                    boolean includeIdTokenClaims = Boolean.TRUE.equals(
                            appConfiguration.getLegacyIdTokenClaims());

                    idToken = authorizationGrant.createIdToken(
                            null, null, accToken, null,
                            null, authorizationGrant, includeIdTokenClaims, idTokenPreProcessing);
                }

                builder.entity(getJSonResponse(accToken,
                        accToken.getTokenType(),
                        accToken.getExpiresIn(),
                        reToken,
                        scope,
                        idToken));
                oAuth2AuditLog.updateOAuth2AuditLog(authorizationGrant, true);
            } else if (gt == GrantType.CLIENT_CREDENTIALS) {
                if (!TokenParamsValidator.validateGrantType(gt, client.getGrantTypes(), appConfiguration.getGrantTypesSupported())) {
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "grant_type is not present in client."), oAuth2AuditLog);
                }

                ClientCredentialsGrant clientCredentialsGrant = authorizationGrantList.createClientCredentialsGrant(new User(), client); // TODO: fix the user arg

                if (scope != null && !scope.isEmpty()) {
                    scope = clientCredentialsGrant.checkScopesPolicy(scope);
                }

                AccessToken accessToken = clientCredentialsGrant.createAccessToken(request.getHeader("X-ClientCert"), new ExecutionContext(request, response)); // create token after scopes are checked

                IdToken idToken = null;
                if (appConfiguration.getOpenidScopeBackwardCompatibility() && clientCredentialsGrant.getScopes().contains("openid")) {
                    boolean includeIdTokenClaims = Boolean.TRUE.equals(
                            appConfiguration.getLegacyIdTokenClaims());
                    idToken = clientCredentialsGrant.createIdToken(
                            null, null, null, null,
                            null, clientCredentialsGrant, includeIdTokenClaims, idTokenPreProcessing);
                }

                oAuth2AuditLog.updateOAuth2AuditLog(clientCredentialsGrant, true);
                builder.entity(getJSonResponse(accessToken,
                        accessToken.getTokenType(),
                        accessToken.getExpiresIn(),
                        null,
                        scope,
                        idToken));
            } else if (gt == GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS) {
                if (!TokenParamsValidator.validateGrantType(gt, client.getGrantTypes(), appConfiguration.getGrantTypesSupported())) {
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "grant_type is not present in client."), oAuth2AuditLog);
                }

                boolean authenticated = false;
                User user = null;
                if (authenticationFilterService.isEnabled()) {
                    String userDn = authenticationFilterService.processAuthenticationFilters(request.getParameterMap());
                    if (StringHelper.isNotEmpty(userDn)) {
                        user = userService.getUserByDn(userDn);
                        authenticated = true;
                    }
                }


                if (!authenticated) {
                    if (externalResourceOwnerPasswordCredentialsService.isEnabled()) {
                        final ExternalResourceOwnerPasswordCredentialsContext context = new ExternalResourceOwnerPasswordCredentialsContext(request, response, appConfiguration, attributeService, userService);
                        context.setUser(user);
                        if (externalResourceOwnerPasswordCredentialsService.executeExternalAuthenticate(context)) {
                            log.trace("RO PC - User is authenticated successfully by external script.");
                            user = context.getUser();
                        }
                    } else {
                        try {
                            authenticated = authenticationService.authenticate(username, password);
                            if (authenticated) {
                                user = authenticationService.getAuthenticatedUser();
                            }
                        } catch (AuthenticationException ex) {
                            log.trace("Failed to authenticate user ", new RuntimeException("User name or password is invalid"));
                        }
                    }
                }

                if (user != null) {
                    ResourceOwnerPasswordCredentialsGrant resourceOwnerPasswordCredentialsGrant = authorizationGrantList.createResourceOwnerPasswordCredentialsGrant(user, client);
                    SessionId sessionId = identity.getSessionId();
                    if (sessionId != null) {
                        resourceOwnerPasswordCredentialsGrant.setAcrValues(OxConstants.SCRIPT_TYPE_INTERNAL_RESERVED_NAME);
                        resourceOwnerPasswordCredentialsGrant.setSessionDn(sessionId.getDn());
                        resourceOwnerPasswordCredentialsGrant.save(); // call save after object modification!!!

                        sessionId.getSessionAttributes().put(Constants.AUTHORIZED_GRANT, gt.getValue());
                        boolean updateResult = sessionIdService.updateSessionId(sessionId, false, true, true);
                        if (!updateResult) {
                            log.debug("Failed to update session entry: '{}'", sessionId.getId());
                        }
                    }


                    RefreshToken reToken = null;
                    if (isRefreshTokenAllowed(client, resourceOwnerPasswordCredentialsGrant)) {
                        reToken = resourceOwnerPasswordCredentialsGrant.createRefreshToken();
                    }

                    if (scope != null && !scope.isEmpty()) {
                        scope = resourceOwnerPasswordCredentialsGrant.checkScopesPolicy(scope);
                    }

                    AccessToken accessToken = resourceOwnerPasswordCredentialsGrant.createAccessToken(request.getHeader("X-ClientCert"), new ExecutionContext(request, response)); // create token after scopes are checked

                    IdToken idToken = null;
                    if (appConfiguration.getOpenidScopeBackwardCompatibility() && resourceOwnerPasswordCredentialsGrant.getScopes().contains("openid")) {
                        boolean includeIdTokenClaims = Boolean.TRUE.equals(
                                appConfiguration.getLegacyIdTokenClaims());
                        idToken = resourceOwnerPasswordCredentialsGrant.createIdToken(
                                null, null, null, null,
                                null, resourceOwnerPasswordCredentialsGrant, includeIdTokenClaims, idTokenPreProcessing);
                    }

                    oAuth2AuditLog.updateOAuth2AuditLog(resourceOwnerPasswordCredentialsGrant, true);
                    builder.entity(getJSonResponse(accessToken,
                            accessToken.getTokenType(),
                            accessToken.getExpiresIn(),
                            reToken,
                            scope,
                            idToken));
                } else {
                    log.debug("Invalid user", new RuntimeException("User is empty"));
                    builder = error(401, TokenErrorResponseType.INVALID_CLIENT, "Invalid user.");
                }
            } else if (gt == GrantType.CIBA) {
                if (!TokenParamsValidator.validateGrantType(gt, client.getGrantTypes(), appConfiguration.getGrantTypesSupported())) {
                    return response(error(400, TokenErrorResponseType.INVALID_GRANT, "Grant types are invalid."), oAuth2AuditLog);
                }

                log.debug("Attempting to find authorizationGrant by authReqId: '{}'", authReqId);
                final CIBAGrant cibaGrant = authorizationGrantList.getCIBAGrant(authReqId);

                log.trace("AuthorizationGrant : '{}'", cibaGrant);

                if (cibaGrant != null) {
                    if (cibaGrant.getClient().getBackchannelTokenDeliveryMode() == BackchannelTokenDeliveryMode.PING ||
                            cibaGrant.getClient().getBackchannelTokenDeliveryMode() == BackchannelTokenDeliveryMode.POLL) {
                        long currentTime = new Date().getTime();
                        Long lastAccess = cibaGrant.getLastAccessControl();
                        if (lastAccess == null) {
                            lastAccess = currentTime;
                        }
                        cibaGrant.setLastAccessControl(currentTime);
                        cibaGrant.save();

                        if (cibaGrant.getUserAuthorization() == CIBAGrantUserAuthorization.AUTHORIZATION_GRANTED
                                && !cibaGrant.isTokensDelivered()) {
                            RefreshToken refToken = cibaGrant.createRefreshToken();
                            log.debug("Issuing refresh token: {}", refToken.getCode());

                            AccessToken accessToken = cibaGrant.createAccessToken(request.getHeader("X-ClientCert"), new ExecutionContext(request, response));
                            log.debug("Issuing access token: {}", accessToken.getCode());

                            IdToken idToken = cibaGrant.createIdToken(
                                    null, null, accessToken, refToken,
                                    null, cibaGrant, false, null);

                            cibaGrant.setTokensDelivered(true);
                            cibaGrant.save();

                            RefreshToken reToken = null;
                            if (isRefreshTokenAllowed(client, cibaGrant)) {
                                reToken = refToken;
                            }

                            if (scope != null && !scope.isEmpty()) {
                                scope = cibaGrant.checkScopesPolicy(scope);
                            }

                            builder.entity(getJSonResponse(accessToken,
                                    accessToken.getTokenType(),
                                    accessToken.getExpiresIn(),
                                    reToken,
                                    scope,
                                    idToken));

                            oAuth2AuditLog.updateOAuth2AuditLog(cibaGrant, true);
                        } else if (cibaGrant.getUserAuthorization() == CIBAGrantUserAuthorization.AUTHORIZATION_PENDING) {
                            int intervalSeconds = appConfiguration.getBackchannelAuthenticationResponseInterval();
                            long timeFromLastAccess = currentTime - lastAccess;

                            if (timeFromLastAccess > intervalSeconds * 1000) {
                                log.debug("Access hasn't been granted yet for authReqId: '{}'", authReqId);
                                builder = error(400, TokenErrorResponseType.AUTHORIZATION_PENDING, "User hasn't answered yet");
                            } else {
                                log.debug("Slow down protection authReqId: '{}'", authReqId);
                                builder = error(400, TokenErrorResponseType.SLOW_DOWN, "Client is asking too fast the token.");
                            }
                        } else if (cibaGrant.getUserAuthorization() == CIBAGrantUserAuthorization.AUTHORIZATION_DENIED) {
                            log.debug("The end-user denied the authorization request for authReqId: '{}'", authReqId);
                            builder = error(400, TokenErrorResponseType.ACCESS_DENIED, "The end-user denied the authorization request.");
                        }
                    } else {
                        log.debug("Client is not using Poll flow authReqId: '{}'", authReqId);
                        builder = error(400, TokenErrorResponseType.UNAUTHORIZED_CLIENT, "The client is not authorized as it is configured in Push Mode");
                    }
                } else {
                    log.debug("AuthorizationGrant is empty by authReqId: '{}'", authReqId);
                    builder = error(400, TokenErrorResponseType.EXPIRED_TOKEN, "Unable to find grant object for given auth_req_id.");
                }
            }
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            builder = Response.status(500);
            log.error(e.getMessage(), e);
        }

        return response(builder, oAuth2AuditLog);
    }

    private boolean isRefreshTokenAllowed(Client client, IAuthorizationGrant grant) {
        if (appConfiguration.getForceOfflineAccessScopeToEnableRefreshToken() && !grant.getScopes().contains(ScopeConstants.OFFLINE_ACCESS)) {
            return false;
        }
        return Arrays.asList(client.getGrantTypes()).contains(GrantType.REFRESH_TOKEN);
    }

    private void validatePKCE(AuthorizationCodeGrant grant, String codeVerifier, OAuth2AuditLog oAuth2AuditLog) {
        log.trace("PKCE validation, code_verifier: {}, code_challenge: {}, method: {}",
                codeVerifier, grant.getCodeChallenge(), grant.getCodeChallengeMethod());

        if (Strings.isNullOrEmpty(grant.getCodeChallenge()) && Strings.isNullOrEmpty(codeVerifier)) {
            return; // if no code challenge then it's valid, no PKCE check
        }

        if (!CodeVerifier.matched(grant.getCodeChallenge(), grant.getCodeChallengeMethod(), codeVerifier)) {
            log.error("PKCE check fails. Code challenge does not match to request code verifier, " +
                    "grantId:" + grant.getGrantId() + ", codeVerifier: " + codeVerifier);
            throw new WebApplicationException(response(error(401, TokenErrorResponseType.INVALID_GRANT, "PKCE check fails. Code challenge does not match to request code verifier."), oAuth2AuditLog));
        }
    }

    private Response response(ResponseBuilder builder, OAuth2AuditLog oAuth2AuditLog) {
        builder.cacheControl(ServerUtil.cacheControl(true, false));
        builder.header("Pragma", "no-cache");

        applicationAuditLogger.sendMessage(oAuth2AuditLog);

        return builder.build();
    }

    private ResponseBuilder error(int p_status, TokenErrorResponseType p_type, String reason) {
        return Response.status(p_status).type(MediaType.APPLICATION_JSON_TYPE).entity(errorResponseFactory.errorAsJson(p_type, reason));
    }

    /**
     * Builds a JSon String with the structure for token issues.
     */
    public String getJSonResponse(AccessToken accessToken, TokenType tokenType,
                                  Integer expiresIn, RefreshToken refreshToken, String scope,
                                  IdToken idToken) {
        JSONObject jsonObj = new JSONObject();
        try {
            jsonObj.put("access_token", accessToken.getCode()); // Required
            jsonObj.put("token_type", tokenType.toString()); // Required
            if (expiresIn != null) { // Optional
                jsonObj.put("expires_in", expiresIn);
            }
            if (refreshToken != null) { // Optional
                jsonObj.put("refresh_token", refreshToken.getCode());
            }
            if (scope != null) { // Optional
                jsonObj.put("scope", scope);
            }
            if (idToken != null) {
                jsonObj.put("id_token", idToken.getCode());
            }
        } catch (JSONException e) {
            log.error(e.getMessage(), e);
        }

        return jsonObj.toString();
    }
}