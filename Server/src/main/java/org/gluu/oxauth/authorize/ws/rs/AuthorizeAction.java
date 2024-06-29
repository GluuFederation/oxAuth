/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.authorize.ws.rs;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.util.Strings;
import org.gluu.jsf2.message.FacesMessages;
import org.gluu.jsf2.service.FacesService;
import org.gluu.model.AuthenticationScriptUsageType;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.oxauth.auth.Authenticator;
import org.gluu.oxauth.i18n.LanguageBean;
import org.gluu.oxauth.model.auth.AuthenticationMode;
import org.gluu.oxauth.model.authorize.*;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.config.Constants;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.exception.AcrChangedException;
import org.gluu.oxauth.model.exception.InvalidJwtException;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.ldap.ClientAuthorization;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.model.session.SessionIdState;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.oxauth.model.util.JwtUtil;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.security.Identity;
import org.gluu.oxauth.service.*;
import org.gluu.oxauth.service.ciba.CibaRequestService;
import org.gluu.oxauth.service.external.ExternalAuthenticationService;
import org.gluu.oxauth.service.external.ExternalConsentGatheringService;
import org.gluu.oxauth.service.external.ExternalPostAuthnService;
import org.gluu.oxauth.service.external.context.ExternalPostAuthnContext;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.persist.exception.EntryPersistenceException;
import org.gluu.service.net.NetworkService;
import org.gluu.util.StringHelper;
import org.gluu.util.locale.LocaleUtil;
import org.slf4j.Logger;

import javax.enterprise.context.RequestScoped;
import javax.faces.application.FacesMessage;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.*;

import static org.gluu.oxauth.service.DeviceAuthorizationService.SESSION_USER_CODE;
/**
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version March 4, 2020
 */
@RequestScoped
@Named
public class AuthorizeAction {

    @Inject
    private Logger log;

    @Inject
    private ClientService clientService;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private RedirectionUriService redirectionUriService;

    @Inject
    private ClientAuthorizationsService clientAuthorizationsService;

    @Inject
    private ExternalAuthenticationService externalAuthenticationService;

    @Inject
    private ExternalConsentGatheringService externalConsentGatheringService;

    @Inject
    private AuthenticationMode defaultAuthenticationMode;

    @Inject
    private LanguageBean languageBean;

    @Inject
    private NetworkService networkService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private FacesService facesService;

    @Inject
    private FacesMessages facesMessages;

    @Inject
    private FacesContext facesContext;

    @Inject
    private ExternalContext externalContext;

    @Inject
    private ConsentGathererService consentGatherer;

    @Inject
    private AuthorizeService authorizeService;

    @Inject
    private RequestParameterService requestParameterService;

    @Inject
    private ScopeChecker scopeChecker;

    @Inject
    private ErrorHandlerService errorHandlerService;

    @Inject
    private AbstractCryptoProvider cryptoProvider;

    @Inject
    private CookieService cookieService;
    
    @Inject
    private Authenticator authenticator;
    
    @Inject
    private AuthenticationService authenticationService;

    @Inject
    private ExternalPostAuthnService externalPostAuthnService;

    @Inject
    private CibaRequestService cibaRequestService;

	@Inject
	private Identity identity;

    @Inject
    private AuthorizeRestWebServiceValidator authorizeRestWebServiceValidator;

    // OAuth 2.0 request parameters
    private String scope;
    private String responseType;
    private String clientId;
    private String redirectUri;
    private String state;

    // OpenID Connect request parameters
    private String responseMode;
    private String nonce;
    private String display;
    private String prompt;
    private Integer maxAge;
    private String uiLocales;
    private String idTokenHint;
    private String loginHint;
    private String acrValues;
    private String amrValues;
    private String request;
    private String requestUri;
    private String codeChallenge;
    private String codeChallengeMethod;
    private String claims;

    // CIBA Request parameter
    private String authReqId;

    // custom oxAuth parameters
    private String sessionId;

    private String allowedScope;

    public void checkUiLocales() {
        List<String> uiLocalesList = null;
        if (StringUtils.isNotBlank(uiLocales)) {
            uiLocalesList = Util.splittedStringAsList(uiLocales, " ");

            List<Locale> supportedLocales = languageBean.getSupportedLocales();
            Locale matchingLocale = LocaleUtil.localeMatch(uiLocalesList, supportedLocales);

            if (matchingLocale != null) {
                languageBean.setLocale(matchingLocale);
            }
        } else {
            Locale requestedLocale = facesContext.getExternalContext().getRequestLocale();
            if (requestedLocale != null) {
                languageBean.setLocale(requestedLocale);
                return;
            }
            
            Locale defaultLocale = facesContext.getApplication().getDefaultLocale();
            if (defaultLocale != null) {
                languageBean.setLocale(defaultLocale);
            }
        }
    }

    public void checkPermissionGranted() {
        try {
            checkPermissionGrantedInternal();
        } catch (Exception e) {
            log.error("Failed to perform checkPermissionGranted()", e);
            permissionDenied();
        }
    }

    public void checkPermissionGrantedInternal() throws IOException {
        if ((clientId == null) || clientId.isEmpty()) {
            log.debug("Permission denied. client_id should be not empty.");
            permissionDenied();
            return;
        }

        Client client = null;
        try {
            client = clientService.getClient(clientId);
        } catch (EntryPersistenceException ex) {
            log.debug("Permission denied. Failed to find client by inum '{}' in LDAP.", clientId, ex);
            permissionDenied();
            return;
        }

        if (client == null) {
            log.debug("Permission denied. Failed to find client_id '{}' in LDAP.", clientId);
            permissionDenied();
            return;
        }

        // Fix the list of scopes in the authorization page. oxAuth #739
        Set<String> grantedScopes = scopeChecker.checkScopesPolicy(client, scope);
        allowedScope = org.gluu.oxauth.model.util.StringUtils.implode(grantedScopes, " ");

        SessionId session = getSession();
        List<Prompt> prompts = Prompt.fromString(prompt, " ");

        try {
            redirectUri = authorizeRestWebServiceValidator.validateRedirectUri(client, redirectUri, state, session != null ? session.getSessionAttributes().get(SESSION_USER_CODE) : null, (HttpServletRequest) externalContext.getRequest());
        } catch (WebApplicationException e) {
            log.debug(e.getMessage(), e);
            permissionDenied();
            return;
        }

        try {
            session = sessionIdService.assertAuthenticatedSessionCorrespondsToNewRequest(session, acrValues);
        } catch (AcrChangedException e) {
            log.debug("There is already existing session which has another acr then {}, session: {}", acrValues, session.getId());
            if (e.isForceReAuthentication()) {
                session = handleAcrChange(session, prompts);
            } else {
                log.error("ACR is changed, please provide a supported and enabled acr value");
                permissionDenied();
                return;
            }
        }

        if (session == null || StringUtils.isBlank(session.getUserDn()) || SessionIdState.AUTHENTICATED != session.getState()) {
            Map<String, String> parameterMap = externalContext.getRequestParameterMap();
            Map<String, String> requestParameterMap = requestParameterService.getAllowedParameters(parameterMap);

            String redirectTo = "/login.xhtml";

            boolean useExternalAuthenticator = externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.INTERACTIVE);
            if (useExternalAuthenticator) {
                List<String> acrValuesList = sessionIdService.acrValuesList(this.acrValues);
                if (acrValuesList.isEmpty()) {
                    acrValuesList = Arrays.asList(defaultAuthenticationMode.getName());
                }

                CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService.determineCustomScriptConfiguration(AuthenticationScriptUsageType.INTERACTIVE, acrValuesList);

                if (customScriptConfiguration == null) {
                    log.error("Failed to get CustomScriptConfiguration. auth_step: {}, acr_values: {}", 1, this.acrValues);
                    permissionDenied();
                    return;
                }

                String acr = customScriptConfiguration.getName();

                requestParameterMap.put(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE, acr);
                requestParameterMap.put("auth_step", Integer.toString(1));

                String tmpRedirectTo = externalAuthenticationService.executeExternalGetPageForStep(customScriptConfiguration, 1);
                if (StringHelper.isNotEmpty(tmpRedirectTo)) {
                    log.trace("Redirect to person authentication login page: {}", tmpRedirectTo);
                    redirectTo = tmpRedirectTo;
                }
            }

            // Store Remote IP
            String remoteIp = networkService.getRemoteIp();
            requestParameterMap.put(Constants.REMOTE_IP, remoteIp);

            // User Code used in Device Authz flow
            if (session != null && session.getSessionAttributes().containsKey(SESSION_USER_CODE)) {
                String userCode = session.getSessionAttributes().get(SESSION_USER_CODE);
                requestParameterMap.put(SESSION_USER_CODE, userCode);
            }

            // Create unauthenticated session
            SessionId unauthenticatedSession = sessionIdService.generateUnauthenticatedSessionId(null, new Date(), SessionIdState.UNAUTHENTICATED, requestParameterMap, false);
            unauthenticatedSession.setSessionAttributes(requestParameterMap);
            unauthenticatedSession.addPermission(clientId, false);
            
            // Copy ACR script parameters
            if (appConfiguration.getKeepAuthenticatorAttributesOnAcrChange()) {
            	authenticationService.copyAuthenticatorExternalAttributes(session, unauthenticatedSession);
            }

            // #1030, fix for flow 4 - transfer previous session permissions to new session
            if (session != null && session.getPermissionGrantedMap() != null && session.getPermissionGrantedMap().getPermissionGranted() != null) {
                for (Map.Entry<String, Boolean> entity : session.getPermissionGrantedMap().getPermissionGranted().entrySet()) {
                    unauthenticatedSession.addPermission(entity.getKey(), entity.getValue());
                }
                sessionIdService.remove(session); // #1030, remove previous session
            }

            boolean persisted = sessionIdService.persistSessionId(unauthenticatedSession, !prompts.contains(Prompt.NONE)); // always persist is prompt is not none
            if (persisted && log.isTraceEnabled()) {
                log.trace("Session '{}' persisted to LDAP", unauthenticatedSession.getId());
            }

            this.sessionId = unauthenticatedSession.getId();
            cookieService.createSessionIdCookie(unauthenticatedSession, false);
            cookieService.creatRpOriginIdCookie(redirectUri);
            identity.setSessionId(unauthenticatedSession);

            Map<String, Object> loginParameters = new HashMap<String, Object>();
            if (requestParameterMap.containsKey(AuthorizeRequestParam.LOGIN_HINT)) {
                loginParameters.put(AuthorizeRequestParam.LOGIN_HINT, requestParameterMap.get(AuthorizeRequestParam.LOGIN_HINT));
            }

            boolean enableRedirect = StringHelper.toBoolean(System.getProperty("gluu.enable-redirect", "false"), false); 
            if (!enableRedirect && redirectTo.toLowerCase().endsWith("xhtml")) {
            	if (redirectTo.toLowerCase().endsWith("postlogin.xhtml")) {
                	authenticator.authenticateWithOutcome();
            	} else {
	            	authenticator.prepareAuthenticationForStep(unauthenticatedSession);
	            	facesService.renderView(redirectTo);
            	}
            } else {
            	facesService.redirectWithExternal(redirectTo, loginParameters);
            }

            return;
        }

        String userCode = session.getSessionAttributes().get(SESSION_USER_CODE);
        if (StringUtils.isBlank(userCode) && StringUtils.isBlank(redirectionUriService.validateRedirectionUri(clientId, redirectUri))) {
            ExternalContext externalContext = facesContext.getExternalContext();
            externalContext.setResponseStatus(HttpServletResponse.SC_BAD_REQUEST);
            externalContext.setResponseContentType(MediaType.APPLICATION_JSON);
            externalContext.getResponseOutputWriter().write(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST_REDIRECT_URI, state, ""));
            facesContext.responseComplete();
        }

        if (log.isTraceEnabled()) {
            log.trace("checkPermissionGranted, userDn = " + session.getUserDn());
        }

        if (prompts.contains(Prompt.SELECT_ACCOUNT)) {
            Map requestParameterMap = requestParameterService.getAllowedParameters(externalContext.getRequestParameterMap());
            facesService.redirect("/selectAccount.xhtml", requestParameterMap);
            return;
        }

        if (prompts.contains(Prompt.NONE) && prompts.size() > 1) {
            invalidRequest();
            return;
        }

        ExternalPostAuthnContext postAuthnContext = new ExternalPostAuthnContext(client, session, (HttpServletRequest)externalContext.getRequest(), (HttpServletResponse) externalContext.getResponse());
        final boolean forceAuthorization = externalPostAuthnService.externalForceAuthorization(client, postAuthnContext);

        final boolean hasConsentPrompt = prompts.contains(Prompt.CONSENT);
        if (!hasConsentPrompt && !forceAuthorization) {
            if (appConfiguration.getTrustedClientEnabled() && client.getTrustedClient()) {
                // if trusted client = true, then skip authorization page and grant access directly
                permissionGranted(session);
                return;
            } else if (ServerUtil.isTrue(appConfiguration.getSkipAuthorizationForOpenIdScopeAndPairwiseId())
                    && SubjectType.PAIRWISE.toString().equals(client.getSubjectType()) && hasOnlyOpenidScope()) {
                // If a client has only openid scope and pairwise id, person should not have to authorize. oxAuth-743
                permissionGranted(session);
                return;
            }

            final User user = sessionIdService.getUser(session);
            ClientAuthorization clientAuthorization = clientAuthorizationsService.find(
                    user.getAttribute("inum"),
                    client.getClientId());
            if (clientAuthorization != null && clientAuthorization.getScopes() != null &&
                    Arrays.asList(clientAuthorization.getScopes()).containsAll(
                            org.gluu.oxauth.model.util.StringUtils.spaceSeparatedToList(scope))) {
                permissionGranted(session);
                return;
            }
        }

        if (externalConsentGatheringService.isEnabled()) {
            if (consentGatherer.isConsentGathered()) {
                log.trace("Consent-gathered flow passed successfully");
                permissionGranted(session);
                return;
            }

            log.trace("Starting external consent-gathering flow");

            boolean result = consentGatherer.configure(session.getUserDn(), clientId, state);
            if (!result) {
                log.error("Failed to initialize external consent-gathering flow.");
                permissionDenied();
                return;
            }
        }
    }

    private SessionId handleAcrChange(SessionId session, List<Prompt> prompts) {
        if (session != null) {
            if (session.getState() == SessionIdState.AUTHENTICATED) {

                if (!prompts.contains(Prompt.LOGIN)) {
                    prompts.add(Prompt.LOGIN);
                }
                session.getSessionAttributes().put("prompt", org.gluu.oxauth.model.util.StringUtils.implode(prompts, " "));
                session.setState(SessionIdState.UNAUTHENTICATED);

                // Update Remote IP
                String remoteIp = networkService.getRemoteIp();
                session.getSessionAttributes().put(Constants.REMOTE_IP, remoteIp);

                final boolean isSessionPersisted = sessionIdService.reinitLogin(session, false);
                if (!isSessionPersisted) {
                    sessionIdService.updateSessionId(session);
                }
            }
        }
        return session;
    }

    private SessionId getSession() {
        return authorizeService.getSession(sessionId);
    }

    public List<org.oxauth.persistence.model.Scope> getScopes() {
        return authorizeService.getScopes(allowedScope);
    }

    public List<String> getRequestedClaims() {
        Set<String> result = new HashSet<String>();
        String requestJwt = request;

        if (StringUtils.isBlank(requestJwt) && StringUtils.isNotBlank(requestUri)) {
            try {
                URI reqUri = new URI(requestUri);
                String reqUriHash = reqUri.getFragment();
                String reqUriWithoutFragment = reqUri.getScheme() + ":" + reqUri.getSchemeSpecificPart();

                javax.ws.rs.client.Client clientRequest = ClientBuilder.newClient();
                try {
	        	    Response clientResponse = clientRequest.target(reqUriWithoutFragment).request().buildGet().invoke();
	        	    clientRequest.close();
	
	                int status = clientResponse.getStatus();
	                if (status == 200) {
	                    String entity = clientResponse.readEntity(String.class);
	
	                    if (StringUtils.isBlank(reqUriHash)) {
	                        requestJwt = entity;
	                    } else {
	                        String hash = Base64Util.base64urlencode(JwtUtil.getMessageDigestSHA256(entity));
	                        if (StringUtils.equals(reqUriHash, hash)) {
	                            requestJwt = entity;
	                        }
	                    }
	                }
                } finally {
                	clientRequest.close();
                }
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }

        if (StringUtils.isNotBlank(requestJwt)) {
            try {
                Client client = clientService.getClient(clientId);

                if (client != null) {
                    JwtAuthorizationRequest jwtAuthorizationRequest = new JwtAuthorizationRequest(appConfiguration, cryptoProvider, request, client);

                    if (jwtAuthorizationRequest.getUserInfoMember() != null) {
                        for (Claim claim : jwtAuthorizationRequest.getUserInfoMember().getClaims()) {
                            result.add(claim.getName());
                        }
                    }

                    if (jwtAuthorizationRequest.getIdTokenMember() != null) {
                        for (Claim claim : jwtAuthorizationRequest.getIdTokenMember().getClaims()) {
                            result.add(claim.getName());
                        }
                    }
                }
            } catch (EntryPersistenceException | InvalidJwtException e) {
                log.error(e.getMessage(), e);
            }
        }

        return new ArrayList<>(result);
    }

    /**
     * Returns the scope of the access request.
     *
     * @return The scope of the access request.
     */
    public String getScope() {
        return scope;
    }

    /**
     * Sets the scope of the access request.
     *
     * @param scope The scope of the access request.
     */
    public void setScope(String scope) {
        this.scope = scope;
    }

    /**
     * Returns the response type: <code>code</code> for requesting an authorization code (authorization code grant) or
     * <strong>token</strong> for requesting an access token (implicit grant).
     *
     * @return The response type.
     */
    public String getResponseType() {
        return responseType;
    }

    /**
     * Sets the response type.
     *
     * @param responseType The response type.
     */
    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    /**
     * Returns the client identifier.
     *
     * @return The client identifier.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Sets the client identifier.
     *
     * @param clientId The client identifier.
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Returns the redirection URI.
     *
     * @return The redirection URI.
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Sets the redirection URI.
     *
     * @param redirectUri The redirection URI.
     */
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    /**
     * Returns an opaque value used by the client to maintain state between the request and callback. The authorization
     * server includes this value when redirecting the user-agent back to the client. The parameter should be used for
     * preventing cross-site request forgery.
     *
     * @return The state between the request and callback.
     */
    public String getState() {
        return state;
    }

    /**
     * Sets the state between the request and callback.
     *
     * @param state The state between the request and callback.
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * Returns the mechanism to be used for returning parameters from the Authorization Endpoint.
     *
     * @return The response mode.
     */
    public String getResponseMode() {
        return responseMode;
    }

    /**
     * Sets the mechanism to be used for returning parameters from the Authorization Endpoint.
     *
     * @param responseMode The response mode.
     */
    public void setResponseMode(String responseMode) {
        this.responseMode = responseMode;
    }

    /**
     * Return a string value used to associate a user agent session with an ID Token, and to mitigate replay attacks.
     *
     * @return The nonce value.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Sets a string value used to associate a user agent session with an ID Token, and to mitigate replay attacks.
     *
     * @param nonce The nonce value.
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * Returns an ASCII string value that specifies how the Authorization Server displays the authentication page
     * to the End-User.
     *
     * @return The display value.
     */
    public String getDisplay() {
        return display;
    }

    /**
     * Sets an ASCII string value that specifies how the Authorization Server displays the authentication page
     * to the End-User.
     *
     * @param display The display value
     */
    public void setDisplay(String display) {
        this.display = display;
    }

    /**
     * Returns a space delimited list of ASCII strings that can contain the values
     * login, consent, select_account, and none.
     *
     * @return A list of prompt options.
     */
    public String getPrompt() {
        return prompt;
    }

    /**
     * Sets a space delimited list of ASCII strings that can contain the values
     * login, consent, select_account, and none.
     *
     * @param prompt A list of prompt options.
     */
    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public Integer getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(Integer maxAge) {
        this.maxAge = maxAge;
    }

    public String getUiLocales() {
        return uiLocales;
    }

    public void setUiLocales(String uiLocales) {
        this.uiLocales = uiLocales;
    }

    public String getIdTokenHint() {
        return idTokenHint;
    }

    public void setIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public void setLoginHint(String loginHint) {
        this.loginHint = StringEscapeUtils.escapeEcmaScript(loginHint);
    }

    public String getAcrValues() {
        return acrValues;
    }

    public void setAcrValues(String acrValues) {
        this.acrValues = acrValues;
    }

    public String getAmrValues() {
        return amrValues;
    }

    public void setAmrValues(String amrValues) {
        this.amrValues = amrValues;
    }

    /**
     * Returns a JWT encoded OpenID Request Object.
     *
     * @return A JWT encoded OpenID Request Object.
     */
    public String getRequest() {
        return request;
    }

    /**
     * Sets a JWT encoded OpenID Request Object.
     *
     * @param request A JWT encoded OpenID Request Object.
     */
    public void setRequest(String request) {
        this.request = request;
    }

    /**
     * Returns an URL that points to an OpenID Request Object.
     *
     * @return An URL that points to an OpenID Request Object.
     */
    public String getRequestUri() {
        return requestUri;
    }

    /**
     * Sets an URL that points to an OpenID Request Object.
     *
     * @param requestUri An URL that points to an OpenID Request Object.
     */
    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String p_sessionId) {
        sessionId = p_sessionId;
    }

    public void permissionGranted() {
        final SessionId session = getSession();
        permissionGranted(session);
    }

    public void permissionGranted(SessionId session) {
        final HttpServletRequest httpRequest = (HttpServletRequest) externalContext.getRequest();
        authorizeService.permissionGranted(httpRequest, session);
    }

    public void permissionDenied() {
        final SessionId session = getSession();
        authorizeService.permissionDenied(session);
    }

    private void authenticationFailedSessionInvalid() {
        facesMessages.add(FacesMessage.SEVERITY_ERROR, "login.errorSessionInvalidMessage");
        facesService.redirect("/error.xhtml");
    }

    public void invalidRequest() {
        log.trace("invalidRequest");
        StringBuilder sb = new StringBuilder();

        sb.append(redirectUri);
        if (redirectUri != null && redirectUri.contains("?")) {
            sb.append("&");
        } else {
            sb.append("?");
        }
        sb.append(errorResponseFactory.getErrorAsQueryString(AuthorizeErrorResponseType.INVALID_REQUEST,
                getState()));

        facesService.redirectToExternalURL(sb.toString());
    }

    public void consentRequired() {
        StringBuilder sb = new StringBuilder();

        sb.append(redirectUri);
        if (redirectUri != null && redirectUri.contains("?")) {
            sb.append("&");
        } else {
            sb.append("?");
        }
        sb.append(errorResponseFactory.getErrorAsQueryString(AuthorizeErrorResponseType.CONSENT_REQUIRED, getState()));

        facesService.redirectToExternalURL(sb.toString());
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public String getClaims() {
        return claims;
    }

    public void setClaims(String claims) {
        this.claims = claims;
    }

    public String getAuthReqId() {
        return authReqId;
    }

    public void setAuthReqId(String authReqId) {
        this.authReqId = authReqId;
    }

    public String getBindingMessage() {
        String bindingMessage = null;

        if (Strings.isNotBlank(getAuthReqId())) {
            final CibaRequestCacheControl cibaRequestCacheControl = cibaRequestService.getCibaRequest(authReqId);

            if (cibaRequestCacheControl != null) {
                bindingMessage = cibaRequestCacheControl.getBindingMessage();
            }
        }

        return bindingMessage;
    }

    public String encodeParameters(String url, Map<String, Object> parameters) {
        if (parameters.isEmpty()) return url;

        StringBuilder builder = new StringBuilder(url);
        for (Map.Entry<String, Object> param : parameters.entrySet()) {
            String parameterName = param.getKey();
            if (!containsParameter(url, parameterName)) {
                Object parameterValue = param.getValue();
                if (parameterValue instanceof Iterable) {
                    for (Object value : (Iterable) parameterValue) {
                        builder.append('&')
                                .append(parameterName)
                                .append('=');
                        if (value != null) {
                            builder.append(encode(value));
                        }
                    }
                } else {
                    builder.append('&')
                            .append(parameterName)
                            .append('=');
                    if (parameterValue != null) {
                        builder.append(encode(parameterValue));
                    }
                }
            }
        }
        if (url.indexOf('?') < 0) {
            builder.setCharAt(url.length(), '?');
        }
        return builder.toString();
    }

    private boolean containsParameter(String url, String parameterName) {
        return url.indexOf('?' + parameterName + '=') > 0 ||
                url.indexOf('&' + parameterName + '=') > 0;
    }

    private String encode(Object value) {
        try {
            return URLEncoder.encode(String.valueOf(value), "UTF-8");
        } catch (UnsupportedEncodingException iee) {
            throw new RuntimeException(iee);
        }
    }

    private boolean hasOnlyOpenidScope() {
        return getScopes() != null && getScopes().size() == 1 && getScopes().get(0).getId().equals("openid");
    }

    protected void handleSessionInvalid() {
        errorHandlerService.handleError(Authenticator.INVALID_SESSION_MESSAGE, AuthorizeErrorResponseType.AUTHENTICATION_SESSION_INVALID, "Create authorization request to start new authentication session.");
    }


    protected void handleScriptError(String facesMessageId) {
        errorHandlerService.handleError(Authenticator.AUTHENTICATION_ERROR_MESSAGE, AuthorizeErrorResponseType.INVALID_AUTHENTICATION_METHOD, "Contact administrator to fix specific ACR method issue.");
    }

}
