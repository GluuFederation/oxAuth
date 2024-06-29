/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service;

import com.google.common.collect.Sets;
import org.apache.commons.lang.StringUtils;
import org.gluu.jsf2.message.FacesMessages;
import org.gluu.jsf2.service.FacesService;
import org.gluu.oxauth.auth.Authenticator;
import org.gluu.oxauth.ciba.CIBAPingCallbackService;
import org.gluu.oxauth.ciba.CIBAPushErrorService;
import org.gluu.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.gluu.oxauth.model.authorize.AuthorizeRequestParam;
import org.gluu.oxauth.model.ciba.PushErrorResponseType;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.security.Identity;
import org.gluu.oxauth.service.ciba.CibaRequestService;
import org.gluu.oxauth.util.RedirectUri;
import org.gluu.oxauth.util.ServerUtil;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;

import javax.enterprise.context.RequestScoped;
import javax.faces.application.FacesMessage;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.gluu.oxauth.model.util.StringUtils.spaceSeparatedToList;

/**
 * @author Yuriy Movchan
 * @author Javier Rojas Blum
 * @version May 9, 2020
 */
@RequestScoped
public class AuthorizeService {

    @Inject
    private Logger log;

    @Inject
    private ClientService clientService;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private CookieService cookieService;

    @Inject
    private ClientAuthorizationsService clientAuthorizationsService;

    @Inject
    private Identity identity;

    @Inject
    private Authenticator authenticator;

    @Inject
    private FacesService facesService;

    @Inject
    private FacesMessages facesMessages;

    @Inject
    private ExternalContext externalContext;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private ScopeService scopeService;

    @Inject
    private RequestParameterService requestParameterService;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Inject
    private CIBAPingCallbackService cibaPingCallbackService;

    @Inject
    private CIBAPushErrorService cibaPushErrorService;

    @Inject
    private CibaRequestService cibaRequestService;

    @Inject
    private DeviceAuthorizationService deviceAuthorizationService;

    public SessionId getSession() {
        return getSession(null);
    }

    public SessionId getSession(String sessionId) {
        if (StringUtils.isBlank(sessionId)) {
            sessionId = cookieService.getSessionIdFromCookie();
            if (StringUtils.isBlank(sessionId)) {
                return null;
            }
        }

        if (!identity.isLoggedIn()) {
            authenticator.authenticateBySessionId(sessionId);
        }

        SessionId ldapSessionId = sessionIdService.getSessionId(sessionId);
        if (ldapSessionId == null) {
            identity.logout();
        }

        return ldapSessionId;
    }

    public void permissionGranted(HttpServletRequest httpRequest, final SessionId session) {
        log.trace("permissionGranted");
        try {
            final User user = sessionIdService.getUser(session);
            if (user == null) {
                log.debug("Permission denied. Failed to find session user: userDn = " + session.getUserDn() + ".");
                permissionDenied(session);
                return;
            }

            String clientId = session.getSessionAttributes().get(AuthorizeRequestParam.CLIENT_ID);
            final Client client = clientService.getClient(clientId);

            String scope = session.getSessionAttributes().get(AuthorizeRequestParam.SCOPE);
            Set<String> scopeSet = Sets.newHashSet(spaceSeparatedToList(scope));
            String responseType = session.getSessionAttributes().get(AuthorizeRequestParam.RESPONSE_TYPE);

            boolean persistDuringImplicitFlow = ServerUtil.isFalse(appConfiguration.getUseCacheForAllImplicitFlowObjects()) || !ResponseType.isImplicitFlow(responseType);
            if (!client.getTrustedClient() && persistDuringImplicitFlow && client.getPersistClientAuthorizations()) {

                clientAuthorizationsService.add(user.getAttribute("inum"), client.getClientId(), scopeSet);
            }
            session.addPermission(clientId, true, scopeSet);
            sessionIdService.updateSessionId(session);
            identity.setSessionId(session);

            // OXAUTH-297 - set session_id cookie
            if (!appConfiguration.getInvalidateSessionCookiesAfterAuthorizationFlow()) {
                cookieService.createSessionIdCookie(session, false);
            }
            Map<String, String> sessionAttribute = requestParameterService.getAllowedParameters(session.getSessionAttributes());

            if (sessionAttribute.containsKey(AuthorizeRequestParam.PROMPT)) {
                List<Prompt> prompts = Prompt.fromString(sessionAttribute.get(AuthorizeRequestParam.PROMPT), " ");
                prompts.remove(Prompt.CONSENT);
                sessionAttribute.put(AuthorizeRequestParam.PROMPT, org.gluu.oxauth.model.util.StringUtils.implodeEnum(prompts, " "));
            }

            final String parametersAsString = requestParameterService.parametersAsString(sessionAttribute);
            String uri = httpRequest.getContextPath() + "/restv1/authorize?" + parametersAsString;
            log.trace("permissionGranted, redirectTo: {}", uri);

            if (invalidateSessionCookiesIfNeeded()) {
                if (!uri.contains(AuthorizeRequestParam.SESSION_ID) && appConfiguration.getSessionIdRequestParameterEnabled()) {
                    uri += "&session_id=" + session.getId();
                }
            }
            facesService.redirectToExternalURL(uri);
        } catch (Exception e) {
            log.error("Unable to perform grant permission", e);
            showErrorPage("login.failedToGrantPermission");
        }
    }

    public void permissionDenied(final SessionId session) {
        try {
            permissionDeniedInternal(session);
        } catch (Exception e) {
            log.error("Unable to perform permission deny", e);
            showErrorPage("login.failedToDeny");
        }
    }

    public void permissionDeniedInternal(final SessionId session) {
        log.trace("permissionDenied");
        invalidateSessionCookiesIfNeeded();

        if (session == null) {
            authenticationFailedSessionInvalid();
            return;
        }

        String baseRedirectUri = session.getSessionAttributes().get(AuthorizeRequestParam.REDIRECT_URI);
        String state = session.getSessionAttributes().get(AuthorizeRequestParam.STATE);
        ResponseMode responseMode = ResponseMode.fromString(session.getSessionAttributes().get(AuthorizeRequestParam.RESPONSE_MODE));
        List<ResponseType> responseType = ResponseType.fromString(session.getSessionAttributes().get(AuthorizeRequestParam.RESPONSE_TYPE), " ");

        RedirectUri redirectUri = new RedirectUri(baseRedirectUri, responseType, responseMode);
        redirectUri.parseQueryString(errorResponseFactory.getErrorAsQueryString(AuthorizeErrorResponseType.ACCESS_DENIED, state));

        // CIBA
        Map<String, String> sessionAttribute = requestParameterService.getAllowedParameters(session.getSessionAttributes());
        if (sessionAttribute.containsKey(AuthorizeRequestParam.AUTH_REQ_ID)) {
            String authReqId = sessionAttribute.get(AuthorizeRequestParam.AUTH_REQ_ID);
            CibaRequestCacheControl request = cibaRequestService.getCibaRequest(authReqId);

            if (request != null  && request.getClient() != null) {
                if (request.getStatus() == CibaRequestStatus.PENDING) {
                    cibaRequestService.removeCibaRequest(authReqId);
                }
                switch (request.getClient().getBackchannelTokenDeliveryMode()) {
                    case POLL:
                        request.setStatus(CibaRequestStatus.DENIED);
                        request.setTokensDelivered(false);
                        cibaRequestService.update(request);
                        break;
                    case PING:
                        request.setStatus(CibaRequestStatus.DENIED);
                        request.setTokensDelivered(false);
                        cibaRequestService.update(request);

                        cibaPingCallbackService.pingCallback(
                                request.getAuthReqId(),
                                request.getClient().getBackchannelClientNotificationEndpoint(),
                                request.getClientNotificationToken()
                        );
                        break;
                    case PUSH:
                        cibaPushErrorService.pushError(
                                request.getAuthReqId(),
                                request.getClient().getBackchannelClientNotificationEndpoint(),
                                request.getClientNotificationToken(),
                                PushErrorResponseType.ACCESS_DENIED,
                                "The end-user denied the authorization request.");
                        break;
                }
            }
        }
        if (sessionAttribute.containsKey(DeviceAuthorizationService.SESSION_USER_CODE)) {
            processDeviceAuthDeniedResponse(sessionAttribute);
        }

        facesService.redirectToExternalURL(redirectUri.toString());
    }

    private void authenticationFailedSessionInvalid() {
        showErrorPage("login.errorSessionInvalidMessage");
    }

    private void showErrorPage(String errorCode) {
        log.debug("Redirect to /error.xhtml page with {} error code.", errorCode);
        facesMessages.add(FacesMessage.SEVERITY_ERROR, errorCode);
        facesService.redirect("/error.xhtml");
    }

    public List<org.oxauth.persistence.model.Scope> getScopes() {
        SessionId session = getSession();
        String scope = session.getSessionAttributes().get("scope");

        return getScopes(scope);

    }

    public List<Scope> getScopes(String scopes) {
        List<org.oxauth.persistence.model.Scope> result = new ArrayList<org.oxauth.persistence.model.Scope>();

        if (scopes != null && !scopes.isEmpty()) {
            String[] scopesName = scopes.split(" ");
            for (String scopeName : scopesName) {
                org.oxauth.persistence.model.Scope s = scopeService.getScopeById(scopeName);
                if (s != null && s.getDescription() != null) {
                    result.add(s);
                }
            }
        }

        return result;
    }

    private boolean invalidateSessionCookiesIfNeeded() {
        if (appConfiguration.getInvalidateSessionCookiesAfterAuthorizationFlow()) {
            return invalidateSessionCookies();
        }
        return false;
    }

    private boolean invalidateSessionCookies() {
        try {
            if (externalContext.getResponse() instanceof HttpServletResponse) {
                final HttpServletResponse httpResponse = (HttpServletResponse) externalContext.getResponse();

                log.trace("Invalidated {} cookie.", CookieService.SESSION_ID_COOKIE_NAME);
                httpResponse.addHeader("Set-Cookie", CookieService.SESSION_ID_COOKIE_NAME + "=deleted; Path=/; Secure; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT;");

                log.trace("Invalidated {} cookie.", CookieService.CONSENT_SESSION_ID_COOKIE_NAME);
                httpResponse.addHeader("Set-Cookie", CookieService.CONSENT_SESSION_ID_COOKIE_NAME + "=deleted; Path=/; Secure; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:01 GMT;");
                return true;
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return false;
    }

    private void processDeviceAuthDeniedResponse(Map<String, String> sessionAttribute) {
        String userCode = sessionAttribute.get(DeviceAuthorizationService.SESSION_USER_CODE);
        DeviceAuthorizationCacheControl cacheData = deviceAuthorizationService.getDeviceAuthzByUserCode(userCode);

        if (cacheData != null && cacheData.getStatus() == DeviceAuthorizationStatus.PENDING) {
            cacheData.setStatus(DeviceAuthorizationStatus.DENIED);
            deviceAuthorizationService.saveInCache(cacheData, true, false);
            deviceAuthorizationService.removeDeviceAuthRequestInCache(userCode, null);
        }
    }
}
