/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.authorize.ws.rs;

import com.google.common.collect.Maps;
import com.wordnik.swagger.annotations.Api;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.gluu.site.ldap.persistence.exception.EntryPersistenceException;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.seam.Component;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Identity;
import org.xdi.oxauth.audit.ApplicationAuditLogger;
import org.xdi.oxauth.auth.Authenticator;
import org.xdi.oxauth.model.audit.Action;
import org.xdi.oxauth.model.audit.OAuth2AuditLog;
import org.xdi.oxauth.model.authorize.*;
import org.xdi.oxauth.model.common.*;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.exception.InvalidJwtException;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.ldap.ClientAuthorizations;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.model.util.Base64Util;
import org.xdi.oxauth.model.util.JwtUtil;
import org.xdi.oxauth.model.util.Util;
import org.xdi.oxauth.service.*;
import org.xdi.oxauth.util.QueryStringDecoder;
import org.xdi.oxauth.util.RedirectUri;
import org.xdi.oxauth.util.RedirectUtil;
import org.xdi.oxauth.util.ServerUtil;
import org.xdi.util.StringHelper;
import org.xdi.util.security.StringEncrypter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.SecurityContext;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.SignatureException;
import java.util.*;
import java.util.Map.Entry;

import static org.xdi.oxauth.model.util.StringUtils.implode;

/**
 * Implementation for request authorization through REST web services.
 *
 * @author Javier Rojas Blum
 * @version August 12, 2017
 */
@Name("requestAuthorizationRestWebService")
@Api(value = "/oxauth/authorize", description = "Authorization Endpoint")
public class AuthorizeRestWebServiceImpl implements AuthorizeRestWebService {

    @Logger
    private Log log;
    @In
    private ApplicationAuditLogger applicationAuditLogger;
    @In
    private ErrorResponseFactory errorResponseFactory;
    @In
    private RedirectionUriService redirectionUriService;
    @In
    private AuthorizationGrantList authorizationGrantList;
    @In
    private ClientService clientService;
    @In
    private UserService userService;
    @In
    private Identity identity;
    @In
    private AuthenticationFilterService authenticationFilterService;
    @In
    private SessionIdService sessionIdService;
    @In
    private ScopeChecker scopeChecker;
    @In
    private SessionId sessionUser;
    @In
    private ClientAuthorizationsService clientAuthorizationsService;
    @In
    private AuthenticationService authenticationService;

    @In
    private AppConfiguration appConfiguration;

    @Override
    public Response requestAuthorizationGet(
            String scope, String responseType, String clientId, String redirectUri, String state, String responseMode,
            String nonce, String display, String prompt, Integer maxAge, String uiLocales, String idTokenHint,
            String loginHint, String acrValues, String amrValues, String request, String requestUri,
            String requestSessionId, String sessionId, String accessToken, String originHeaders,
            String codeChallenge, String codeChallengeMethod, String customResponseHeaders,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse, SecurityContext securityContext) {
        return requestAuthorization(scope, responseType, clientId, redirectUri, state, responseMode, nonce, display,
                prompt, maxAge, uiLocales, idTokenHint, loginHint, acrValues, amrValues, request, requestUri,
                requestSessionId, sessionId, accessToken, HttpMethod.GET, originHeaders, codeChallenge,
                codeChallengeMethod, customResponseHeaders, httpRequest, httpResponse, securityContext);
    }

    @Override
    public Response requestAuthorizationPost(
            String scope, String responseType, String clientId, String redirectUri, String state, String responseMode,
            String nonce, String display, String prompt, Integer maxAge, String uiLocales, String idTokenHint,
            String loginHint, String acrValues, String amrValues, String request, String requestUri,
            String requestSessionId, String sessionId, String accessToken, String originHeaders,
            String codeChallenge, String codeChallengeMethod, String customResponseHeaders,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse, SecurityContext securityContext) {
        return requestAuthorization(scope, responseType, clientId, redirectUri, state, responseMode, nonce, display,
                prompt, maxAge, uiLocales, idTokenHint, loginHint, acrValues, amrValues, request, requestUri,
                requestSessionId, sessionId, accessToken, HttpMethod.POST, originHeaders, codeChallenge,
                codeChallengeMethod, customResponseHeaders, httpRequest, httpResponse, securityContext);
    }

    public Response requestAuthorization(
            String scope, String responseType, String clientId, String redirectUri, String state, String respMode,
            String nonce, String display, String prompt, Integer maxAge, String uiLocalesStr, String idTokenHint,
            String loginHint, String acrValuesStr, String amrValuesStr, String request, String requestUri, String requestSessionId,
            String sessionId, String accessToken, String method, String originHeaders,
            String codeChallenge, String codeChallengeMethod, String customRespHeaders,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse, SecurityContext securityContext) {
        scope = ServerUtil.urlDecode(scope); // it may be encoded in uma case

        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(httpRequest), Action.USER_AUTHORIZATION);
        oAuth2AuditLog.setClientId(clientId);
        oAuth2AuditLog.setScope(scope);

        // ATTENTION : please do not add more parameter in this debug method because it will not work with Seam 2.2.2.Final ,
        // there is limit of 10 parameters (hardcoded), see: org.jboss.seam.core.Interpolator#interpolate
        log.debug("Attempting to request authorization: "
                        + "responseType = {0}, clientId = {1}, scope = {2}, redirectUri = {3}, nonce = {4}, "
                        + "state = {5}, request = {6}, isSecure = {7}, requestSessionId = {8}, sessionId = {9}",
                responseType, clientId, scope, redirectUri, nonce,
                state, request, securityContext.isSecure(), requestSessionId, sessionId);

        log.debug("Attempting to request authorization: "
                        + "acrValues = {0}, amrValues = {1}, originHeaders = {2}, codeChallenge = {3}, codeChallengeMethod = {4}",
                acrValuesStr, amrValuesStr, originHeaders, codeChallenge, codeChallengeMethod);

        ResponseBuilder builder = Response.ok();

        List<String> uiLocales = null;
        if (StringUtils.isNotBlank(uiLocalesStr)) {
            uiLocales = Util.splittedStringAsList(uiLocalesStr, " ");
        }

        List<ResponseType> responseTypes = ResponseType.fromString(responseType, " ");
        List<Prompt> prompts = Prompt.fromString(prompt, " ");
        List<String> acrValues = Util.splittedStringAsList(acrValuesStr, " ");
        List<String> amrValues = Util.splittedStringAsList(amrValuesStr, " ");

        ResponseMode responseMode = ResponseMode.getByValue(respMode);

        User user = sessionUser != null && StringUtils.isNotBlank(sessionUser.getUserDn()) ?
                userService.getUserByDn(sessionUser.getUserDn()) : null;

        try {
            Map<String, String> customResponseHeaders = Util.jsonObjectArrayStringAsMap(customRespHeaders);

            sessionIdService.assertAuthenticatedSessionCorrespondsToNewRequest(sessionUser, acrValuesStr);

            if (!AuthorizeParamsValidator.validateParams(responseType, clientId, prompts, nonce, request, requestUri)) {
                if (clientId != null && redirectUri != null && redirectionUriService.validateRedirectionUri(clientId, redirectUri) != null) {
                    RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);
                    redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                            AuthorizeErrorResponseType.INVALID_REQUEST, state));

                    builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                } else {
                    builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                    builder.entity(errorResponseFactory.getErrorAsJson(
                            AuthorizeErrorResponseType.INVALID_REQUEST, state));
                }
            } else {
                Client client = clientService.getClient(clientId);
                if (CollectionUtils.isEmpty(acrValues) && client != null && !ArrayUtils.isEmpty(client.getDefaultAcrValues())) {
                    acrValues = new ArrayList<String>();
                    acrValues.addAll(Arrays.asList(client.getDefaultAcrValues()));
                }

                JwtAuthorizationRequest jwtAuthorizationRequest = null;

                if (client != null) {
                    List<String> scopes = new ArrayList<String>();
                    if (StringHelper.isNotEmpty(scope)) {
                        Set<String> grantedScopes = scopeChecker.checkScopesPolicy(client, scope);
                        scopes.addAll(grantedScopes);
                    }

                    // Validate redirectUri
                    redirectUri = redirectionUriService.validateRedirectionUri(clientId, redirectUri);
                    boolean validRedirectUri = redirectUri != null;

                    if (AuthorizeParamsValidator.validateResponseTypes(responseTypes, client)) {
                        if (validRedirectUri) {

                            if (StringUtils.isNotBlank(accessToken)) {
                                AuthorizationGrant authorizationGrant = authorizationGrantList.getAuthorizationGrantByAccessToken(accessToken);

                                if (authorizationGrant == null) {
                                    RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);
                                    redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                                            AuthorizeErrorResponseType.ACCESS_DENIED, state));

                                    builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                    applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                    return builder.build();
                                } else {
                                    oAuth2AuditLog.setUsername(authorizationGrant.getUserId());
                                    user = userService.getUser(authorizationGrant.getUserId());
                                    sessionUser = sessionIdService.generateAuthenticatedSessionId(user.getDn(), prompt);
                                    sessionUser.addPermission(client.getClientId(), true);
                                }
                            }

                            if (StringUtils.isNotBlank(requestUri)) {
                                boolean validRequestUri = false;
                                try {
                                    URI reqUri = new URI(requestUri);
                                    String reqUriHash = reqUri.getFragment();
                                    String reqUriWithoutFragment = reqUri.getScheme() + ":" + reqUri.getSchemeSpecificPart();

                                    ClientRequest clientRequest = new ClientRequest(reqUriWithoutFragment);
                                    clientRequest.setHttpMethod(HttpMethod.GET);

                                    ClientResponse<String> clientResponse = clientRequest.get(String.class);
                                    int status = clientResponse.getStatus();

                                    if (status == 200) {
                                        request = clientResponse.getEntity(String.class);

                                        if (StringUtils.isBlank(reqUriHash)) {
                                            validRequestUri = true;
                                        } else {
                                            String hash = Base64Util.base64urlencode(JwtUtil.getMessageDigestSHA256(request));
                                            validRequestUri = StringUtils.equals(reqUriHash, hash);
                                        }
                                    }

                                    if (validRequestUri) {
                                        requestUri = null;
                                    } else {
                                        RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);
                                        redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                                                AuthorizeErrorResponseType.INVALID_REQUEST_URI, state));

                                        builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                        applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                        return builder.build();
                                    }
                                } catch (URISyntaxException e) {
                                    log.error(e.getMessage(), e);
                                } catch (UnknownHostException e) {
                                    log.error(e.getMessage(), e);
                                } catch (ConnectException e) {
                                    log.error(e.getMessage(), e);
                                } catch (Exception e) {
                                    log.error(e.getMessage(), e);
                                }
                            }

                            boolean invalidOpenidRequestObject = false;
                            if (StringUtils.isNotBlank(request)) {
                                try {
                                    jwtAuthorizationRequest = new JwtAuthorizationRequest(appConfiguration, request, client);

                                    if (!jwtAuthorizationRequest.getResponseTypes().containsAll(responseTypes)
                                            || !responseTypes.containsAll(jwtAuthorizationRequest.getResponseTypes())) {
                                        throw new InvalidJwtException("The responseType parameter is not the same in the JWT");
                                    } else if (jwtAuthorizationRequest.getClientId() != null
                                            && !jwtAuthorizationRequest.getClientId().equals(clientId)) {
                                        throw new InvalidJwtException("The clientId parameter is not the same in the JWT");
                                    } else if (!jwtAuthorizationRequest.getScopes().containsAll(scopes)
                                            || !scopes.containsAll(jwtAuthorizationRequest.getScopes())) {
                                        throw new InvalidJwtException("The scope parameter is not the same in the JWT");
                                    } else if (jwtAuthorizationRequest.getRedirectUri() != null
                                            && !jwtAuthorizationRequest.getRedirectUri().equals(redirectUri)) {
                                        throw new InvalidJwtException("The redirectUri parameter is not the same in the JWT");
                                    } else if (jwtAuthorizationRequest.getState() != null && StringUtils.isNotBlank(state)
                                            && !jwtAuthorizationRequest.getState().equals(state)) {
                                        throw new InvalidJwtException("The state parameter is not the same in the JWT");
                                    } else if (jwtAuthorizationRequest.getNonce() != null && StringUtils.isNotBlank(nonce)
                                            && !jwtAuthorizationRequest.getNonce().equals(nonce)) {
                                        throw new InvalidJwtException("The nonce parameter is not the same in the JWT");
                                    } else if (jwtAuthorizationRequest.getDisplay() != null && StringUtils.isNotBlank(display)
                                            && !jwtAuthorizationRequest.getDisplay().getParamName().equals(display)) {
                                        throw new InvalidJwtException("The display parameter is not the same in the JWT");
                                    } else if (!jwtAuthorizationRequest.getPrompts().isEmpty() && !prompts.isEmpty()
                                            && !jwtAuthorizationRequest.getPrompts().containsAll(prompts)) {
                                        throw new InvalidJwtException("The prompt parameter is not the same in the JWT");
                                    } else if (jwtAuthorizationRequest.getIdTokenMember() != null
                                            && jwtAuthorizationRequest.getIdTokenMember().getMaxAge() != null && maxAge != null
                                            && !jwtAuthorizationRequest.getIdTokenMember().getMaxAge().equals(maxAge)) {
                                        throw new InvalidJwtException("The maxAge parameter is not the same in the JWT");
                                    }
                                } catch (InvalidJwtException e) {
                                    invalidOpenidRequestObject = true;
                                    log.debug("Invalid JWT authorization request. Exception = {0}, Message = {1}", e,
                                            e.getClass().getName(), e.getMessage());
                                } catch (Exception e) {
                                    invalidOpenidRequestObject = true;
                                    log.debug("Invalid JWT authorization request. Exception = {0}, Message = {1}", e,
                                            e.getClass().getName(), e.getMessage());
                                }
                            }
                            if (invalidOpenidRequestObject) {
                                RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);

                                redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                                        AuthorizeErrorResponseType.INVALID_OPENID_REQUEST_OBJECT, state));

                                builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                            } else {
                                AuthorizationGrant authorizationGrant = null;
                                RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);

                                if (jwtAuthorizationRequest != null && jwtAuthorizationRequest.getIdTokenMember() != null) {
                                    Claim userIdClaim = jwtAuthorizationRequest.getIdTokenMember().getClaim(JwtClaimName.SUBJECT_IDENTIFIER);
                                    if (userIdClaim != null && userIdClaim.getClaimValue() != null
                                            && userIdClaim.getClaimValue().getValue() != null) {
                                        String userIdClaimValue = userIdClaim.getClaimValue().getValue();

                                        if (user != null) {
                                            String userId = user.getUserId();

                                            if (!userId.equalsIgnoreCase(userIdClaimValue)) {
                                                redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                                                        AuthorizeErrorResponseType.USER_MISMATCHED, state));

                                                builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                                applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                                return builder.build();
                                            }
                                        }
                                    }
                                }

                                if (user == null) {
                                    identity.logout();
                                    if (prompts.contains(Prompt.NONE)) {
                                        if (authenticationFilterService.isEnabled()) {
                                            Map<String, String> params;
                                            if (method.equals(HttpMethod.GET)) {
                                                params = QueryStringDecoder.decode(httpRequest.getQueryString());
                                            } else {
                                                params = getGenericRequestMap(httpRequest);
                                            }

                                            String userDn = authenticationFilterService.processAuthenticationFilters(params);
                                            if (userDn != null) {
                                                Map<String, String> genericRequestMap = getGenericRequestMap(httpRequest);

                                                Map<String, String> parameterMap = Maps.newHashMap(genericRequestMap);
                                                Map<String, String> requestParameterMap = authenticationService.getAllowedParameters(parameterMap);

                                                sessionUser = sessionIdService.generateAuthenticatedSessionId(userDn, prompt);
                                                sessionUser.setSessionAttributes(requestParameterMap);

                                                sessionIdService.createSessionIdCookie(sessionUser.getId(), sessionUser.getSessionState(), httpResponse);
                                                sessionIdService.updateSessionId(sessionUser);
                                                user = userService.getUserByDn(sessionUser.getUserDn());

                                                Authenticator authenticator = (Authenticator) Component.getInstance(Authenticator.class, true);
                                                authenticator.authenticateExternallyWebService(user.getUserId());
                                                identity.addRole("user");
                                            } else {
                                                redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                                                        AuthorizeErrorResponseType.LOGIN_REQUIRED, state));

                                                builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                                applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                                return builder.build();
                                            }
                                        } else {
                                            redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                                                    AuthorizeErrorResponseType.LOGIN_REQUIRED, state));

                                            builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                            applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                            return builder.build();
                                        }
                                    } else {
                                        if (prompts.contains(Prompt.LOGIN)) {
                                            endSession(sessionId, httpRequest, httpResponse);
                                            sessionId = null;
                                            prompts.remove(Prompt.LOGIN);
                                        }

                                        redirectToAuthorizationPage(redirectUriResponse, responseTypes, scope, clientId,
                                                redirectUri, state, responseMode, nonce, display, prompts, maxAge, uiLocales,
                                                idTokenHint, loginHint, acrValues, amrValues, request, requestUri, originHeaders,
                                                codeChallenge, codeChallengeMethod, sessionId);
                                        builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                        applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                        return builder.build();
                                    }
                                }

                                oAuth2AuditLog.setUsername(user.getUserId());

                                ClientAuthorizations clientAuthorizations = clientAuthorizationsService.findClientAuthorizations(user.getAttribute("inum"), client.getClientId());
                                if (clientAuthorizations != null && clientAuthorizations.getScopes() != null &&
                                        Arrays.asList(clientAuthorizations.getScopes()).containsAll(scopes)) {
                                    sessionUser.addPermission(clientId, true);
                                }
                                if (prompts.contains(Prompt.NONE) && client.getTrustedClient()) {
                                    sessionUser.addPermission(clientId, true);
                                }

                                if (prompts.contains(Prompt.LOGIN)) {
                                    endSession(sessionId, httpRequest, httpResponse);
                                    sessionId = null;
                                    prompts.remove(Prompt.LOGIN);

                                    redirectToAuthorizationPage(redirectUriResponse, responseTypes, scope, clientId,
                                            redirectUri, state, responseMode, nonce, display, prompts, maxAge, uiLocales, idTokenHint,
                                            loginHint, acrValues, amrValues, request, requestUri, originHeaders,
                                            codeChallenge, codeChallengeMethod, sessionId);
                                    builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                    applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                    return builder.build();
                                }

                                if (prompts.contains(Prompt.CONSENT) || !sessionUser.isPermissionGrantedForClient(clientId)) {
                                    prompts.remove(Prompt.CONSENT);

                                    redirectToAuthorizationPage(redirectUriResponse, responseTypes, scope, clientId,
                                            redirectUri, state, responseMode, nonce, display, prompts, maxAge, uiLocales, idTokenHint,
                                            loginHint, acrValues, amrValues, request, requestUri, originHeaders,
                                            codeChallenge, codeChallengeMethod, sessionId);
                                    builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                    applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                    return builder.build();
                                }

                                // OXAUTH-37 : Validate authentication max age
                                boolean validAuthenticationMaxAge = true;
                                Integer authenticationMaxAge = null;
                                if (maxAge != null) {
                                    authenticationMaxAge = maxAge;
                                } else if (!invalidOpenidRequestObject && jwtAuthorizationRequest != null
                                        && jwtAuthorizationRequest.getIdTokenMember() != null
                                        && jwtAuthorizationRequest.getIdTokenMember().getMaxAge() != null) {
                                    authenticationMaxAge = jwtAuthorizationRequest.getIdTokenMember().getMaxAge();
                                }
                                GregorianCalendar now = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
                                GregorianCalendar userAuthenticationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
                                userAuthenticationTime.setTime(sessionUser.getAuthenticationTime());
                                if (authenticationMaxAge != null) {
                                    userAuthenticationTime.add(Calendar.SECOND, authenticationMaxAge);
                                    validAuthenticationMaxAge = userAuthenticationTime.after(now);
                                } else if (client.getDefaultMaxAge() != null) {
                                    userAuthenticationTime.add(Calendar.SECOND, client.getDefaultMaxAge());
                                    validAuthenticationMaxAge = userAuthenticationTime.after(now);
                                }
                                if (!validAuthenticationMaxAge) {
                                    endSession(sessionId, httpRequest, httpResponse);
                                    sessionId = null;

                                    redirectToAuthorizationPage(redirectUriResponse, responseTypes, scope, clientId,
                                            redirectUri, state, responseMode, nonce, display, prompts, maxAge, uiLocales, idTokenHint,
                                            loginHint, acrValues, amrValues, request, requestUri, originHeaders,
                                            codeChallenge, codeChallengeMethod, sessionId);
                                    builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);
                                    applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                    return builder.build();
                                }

                                AuthorizationCode authorizationCode = null;
                                if (responseTypes.contains(ResponseType.CODE)) {
                                    authorizationGrant = authorizationGrantList.createAuthorizationCodeGrant(user, client,
                                            sessionUser.getAuthenticationTime());
                                    authorizationGrant.setNonce(nonce);
                                    authorizationGrant.setJwtAuthorizationRequest(jwtAuthorizationRequest);
                                    authorizationGrant.setScopes(scopes);
                                    authorizationGrant.setCodeChallenge(codeChallenge);
                                    authorizationGrant.setCodeChallengeMethod(codeChallengeMethod);

                                    // Store acr_values
                                    authorizationGrant.setAcrValues(acrValuesStr);
                                    authorizationGrant.setSessionDn(sessionUser.getDn());
                                    authorizationGrant.save(); // call save after object modification!!!

                                    authorizationCode = authorizationGrant.getAuthorizationCode();

                                    redirectUriResponse.addResponseParameter("code", authorizationCode.getCode());
                                }

                                AccessToken newAccessToken = null;
                                if (responseTypes.contains(ResponseType.TOKEN)) {
                                    if (authorizationGrant == null) {
                                        authorizationGrant = authorizationGrantList.createImplicitGrant(user, client,
                                                sessionUser.getAuthenticationTime());
                                        authorizationGrant.setNonce(nonce);
                                        authorizationGrant.setJwtAuthorizationRequest(jwtAuthorizationRequest);
                                        authorizationGrant.setScopes(scopes);

                                        // Store acr_values
                                        authorizationGrant.setAcrValues(acrValuesStr);
                                        authorizationGrant.setSessionDn(sessionUser.getDn());
                                        authorizationGrant.save(); // call save after object modification!!!
                                    }
                                    newAccessToken = authorizationGrant.createAccessToken();

                                    redirectUriResponse.addResponseParameter(AuthorizeResponseParam.ACCESS_TOKEN, newAccessToken.getCode());
                                    redirectUriResponse.addResponseParameter(AuthorizeResponseParam.TOKEN_TYPE, newAccessToken.getTokenType().toString());
                                    redirectUriResponse.addResponseParameter(AuthorizeResponseParam.EXPIRES_IN, newAccessToken.getExpiresIn() + "");
                                }

                                if (responseTypes.contains(ResponseType.ID_TOKEN)) {
                                    boolean includeIdTokenClaims = Boolean.TRUE.equals(appConfiguration.getLegacyIdTokenClaims());
                                    if (authorizationGrant == null) {
                                        includeIdTokenClaims = true;
                                        authorizationGrant = authorizationGrantList.createAuthorizationGrant(user, client,
                                                sessionUser.getAuthenticationTime());
                                        authorizationGrant.setNonce(nonce);
                                        authorizationGrant.setJwtAuthorizationRequest(jwtAuthorizationRequest);
                                        authorizationGrant.setScopes(scopes);

                                        // Store authentication acr values
                                        authorizationGrant.setAcrValues(acrValuesStr);
                                        authorizationGrant.setSessionDn(sessionUser.getDn());
                                        authorizationGrant.save(); // call save after object modification, call is asynchronous!!!
                                    }
                                    IdToken idToken = authorizationGrant.createIdToken(
                                            nonce, authorizationCode, newAccessToken, authorizationGrant, includeIdTokenClaims);

                                    redirectUriResponse.addResponseParameter(AuthorizeResponseParam.ID_TOKEN, idToken.getCode());
                                }

                                if (authorizationGrant != null && StringHelper.isNotEmpty(acrValuesStr)) {
                                    redirectUriResponse.addResponseParameter(AuthorizeResponseParam.ACR_VALUES, acrValuesStr);
                                }

                                //if (Boolean.valueOf(requestSessionId) && StringUtils.isBlank(sessionId) &&
                                if (sessionUser.getId() == null) {
                                    final SessionId newSessionUser = sessionIdService.generateAuthenticatedSessionId(sessionUser.getUserDn(), prompt);
                                    String newSessionId = newSessionUser.getId();
                                    sessionUser.setId(newSessionId);
                                    log.trace("newSessionId = {0}", newSessionId);
                                }
                                redirectUriResponse.addResponseParameter(AuthorizeResponseParam.SESSION_ID, sessionUser.getId());
                                redirectUriResponse.addResponseParameter(AuthorizeResponseParam.SESSION_STATE, sessionUser.getSessionState());
                                redirectUriResponse.addResponseParameter(AuthorizeResponseParam.STATE, state);
                                if (scope != null && !scope.isEmpty()) {
                                    scope = authorizationGrant.checkScopesPolicy(scope);

                                    redirectUriResponse.addResponseParameter(AuthorizeResponseParam.SCOPE, scope);
                                }

                                clientService.updatAccessTime(client, false);
                                oAuth2AuditLog.setSuccess(true);

                                builder = RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest);

                                if (appConfiguration.getCustomHeadersWithAuthorizationResponse()) {
                                    for (String key : customResponseHeaders.keySet()) {
                                        builder.header(key, customResponseHeaders.get(key));
                                    }
                                }
                            }
                        } else { // Invalid redirectUri
                            builder = error(Response.Status.BAD_REQUEST,
                                    AuthorizeErrorResponseType.INVALID_REQUEST_REDIRECT_URI, state); // 400
                        }
                    } else { // Invalid responseTypes
                        builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                        builder.entity(errorResponseFactory.getErrorAsJson(
                                AuthorizeErrorResponseType.UNSUPPORTED_RESPONSE_TYPE, state));
                    }
                } else {
                    builder = error(Response.Status.UNAUTHORIZED, AuthorizeErrorResponseType.UNAUTHORIZED_CLIENT, state);
                }
            }
//        } catch (AcrChangedException e) {
//            builder = Response.status(Response.Status.UNAUTHORIZED).entity("Session already exist with ACR that is different " +
//                    "than the one send with this authorization request. Please perform logout in order to login with another ACR. ACR: " + acrValuesStr);
//            log.error(e.getMessage(), e);
        } catch (AcrChangedException e) { // Acr changed
            log.error("ACR is changed, please use prompt=login in order to alter existing session.");
            log.error(e.getMessage(), e);

            RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);
            redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                    AuthorizeErrorResponseType.SESSION_SELECTION_REQUIRED, state));
            redirectUriResponse.addResponseParameter("hint", "Use prompt=login in order to alter existing session.");
            applicationAuditLogger.sendMessage(oAuth2AuditLog);
            return RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest).build();
        } catch (EntryPersistenceException e) { // Invalid clientId
            builder = error(Response.Status.UNAUTHORIZED, AuthorizeErrorResponseType.UNAUTHORIZED_CLIENT, state);
            log.error(e.getMessage(), e);
        } catch (SignatureException e) {
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()); // 500
            log.error(e.getMessage(), e);
        } catch (StringEncrypter.EncryptionException e) {
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()); // 500
            log.error(e.getMessage(), e);
        } catch (InvalidJwtException e) {
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()); // 500
            log.error(e.getMessage(), e);
        } catch (Exception e) {
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()); // 500
            log.error(e.getMessage(), e);
        }

        applicationAuditLogger.sendMessage(oAuth2AuditLog);
        return builder.build();
    }

    /**
     * 1) https://ce-dev.gluu.org/oxauth/authorize -> session created with parameter list 1
     * 2) https://ce-dev.gluu.org/oxauth/seam/resource/restv1/oxauth/authorize -> with parameter list 2
     * <p/>
     * Second call will try to reuse session data from call 1 (parameter list1). Here we overriding them.
     *
     * @param httpRequest http request
     * @param prompts     prompts
     */
    private void overrideUnauthenticatedSessionParameters(HttpServletRequest httpRequest, List<Prompt> prompts) {
        if (sessionUser != null && sessionUser.getState() != SessionIdState.AUTHENTICATED) {
            Map<String, String> genericRequestMap = getGenericRequestMap(httpRequest);

            Map<String, String> parameterMap = Maps.newHashMap(genericRequestMap);
            Map<String, String> requestParameterMap = authenticationService.getAllowedParameters(parameterMap);

            sessionUser.setUserDn(null);
            sessionUser.setSessionAttributes(requestParameterMap);
            boolean persisted = sessionIdService.persistSessionId(sessionUser, !prompts.contains(Prompt.NONE));
            if (persisted) {
                if (log.isTraceEnabled()) {
                    log.trace("Session '{0}' persisted to LDAP", sessionUser.getId());
                }
            } else {
                log.error("Failed to persisted session: {0}", sessionUser.getId());
            }
        }
    }

    private Map<String, String> getGenericRequestMap(HttpServletRequest httpRequest) {
        Map<String, String> result = new HashMap<String, String>();
        for (Entry<String, String[]> entry : httpRequest.getParameterMap().entrySet()) {
            result.put(entry.getKey(), entry.getValue()[0]);
        }

        return result;
    }

    private ResponseBuilder error(Response.Status p_status, AuthorizeErrorResponseType p_type, String p_state) {
        return Response.status(p_status.getStatusCode()).entity(errorResponseFactory.getErrorAsJson(p_type, p_state));
    }

    private void redirectToAuthorizationPage(
            RedirectUri redirectUriResponse, List<ResponseType> responseTypes, String scope, String clientId,
            String redirectUri, String state, ResponseMode responseMode, String nonce, String display,
            List<Prompt> prompts, Integer maxAge, List<String> uiLocales, String idTokenHint, String loginHint,
            List<String> acrValues, List<String> amrValues, String request, String requestUri, String originHeaders,
            String codeChallenge, String codeChallengeMethod, String sessionId) {

        redirectUriResponse.setBaseRedirectUri(appConfiguration.getAuthorizationPage());
        redirectUriResponse.setResponseMode(ResponseMode.QUERY);

        // oAuth parameters
        String responseType = implode(responseTypes, " ");
        if (StringUtils.isNotBlank(responseType)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.RESPONSE_TYPE, responseType);
        }
        if (StringUtils.isNotBlank(scope)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.SCOPE, scope);
        }
        if (StringUtils.isNotBlank(clientId)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.CLIENT_ID, clientId);
        }
        if (StringUtils.isNotBlank(redirectUri)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.REDIRECT_URI, redirectUri);
        }
        if (StringUtils.isNotBlank(state)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.STATE, state);
        }
        if (responseMode != null) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.RESPONSE_MODE, responseMode.getParamName());
        }

        // OIC parameters
        if (StringUtils.isNotBlank(nonce)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.NONCE, nonce);
        }
        if (StringUtils.isNotBlank(display)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.DISPLAY, display);
        }
        String prompt = implode(prompts, " ");
        if (StringUtils.isNotBlank(prompt)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.PROMPT, prompt);
        }
        if (maxAge != null) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.MAX_AGE, maxAge.toString());
        }
        String uiLocalesStr = implode(uiLocales, " ");
        if (StringUtils.isNotBlank(uiLocalesStr)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.UI_LOCALES, uiLocalesStr);
        }
        if (StringUtils.isNotBlank(idTokenHint)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.ID_TOKEN_HINT, idTokenHint);
        }
        if (StringUtils.isNotBlank(loginHint)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.LOGIN_HINT, loginHint);
        }
        String acrValuesStr = implode(acrValues, " ");
        if (StringUtils.isNotBlank(acrValuesStr)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.ACR_VALUES, acrValuesStr);
        }
        String amrValuesStr = implode(amrValues, " ");
        if (StringUtils.isNotBlank(amrValuesStr)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.AMR_VALUES, amrValuesStr);
        }
        if (StringUtils.isNotBlank(request)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.REQUEST, request);
        }
        if (StringUtils.isNotBlank(requestUri)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.REQUEST_URI, requestUri);
        }
        if (StringUtils.isNotBlank(codeChallenge)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.CODE_CHALLENGE, codeChallenge);
        }
        if (StringUtils.isNotBlank(codeChallengeMethod)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.CODE_CHALLENGE_METHOD, codeChallengeMethod);
        }
        if (StringUtils.isNotBlank(sessionId)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.SESSION_ID, sessionId);
        }

        // mod_ox param
        if (StringUtils.isNotBlank(originHeaders)) {
            redirectUriResponse.addResponseParameter(AuthorizeRequestParam.ORIGIN_HEADERS, originHeaders);
        }
    }

    private void endSession(String sessionId, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        identity.logout();
        sessionUser.setUserDn(null);
        sessionUser.setAuthenticationTime(null);


        String id = sessionId;
        if (StringHelper.isEmpty(id)) {
            id = sessionIdService.getSessionIdFromCookie(httpRequest);
        }

        if (StringHelper.isNotEmpty(id)) {
            SessionId ldapSessionId = sessionIdService.getSessionId(id);
            if (ldapSessionId != null) {
                boolean result = sessionIdService.remove(ldapSessionId);
                if (!result) {
                    log.error("Failed to remove session_id '{0}' from LDAP", id);
                }
            } else {
                log.error("Failed to load session from LDAP by session_id: '{0}'", id);
            }
        }

        sessionIdService.removeSessionIdCookie(httpResponse);
    }
}