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
import org.gluu.model.security.Identity;
import org.gluu.oxauth.auth.Authenticator;
import org.gluu.oxauth.ciba.CIBAPingCallbackProxy;
import org.gluu.oxauth.ciba.CIBAPushErrorProxy;
import org.gluu.oxauth.ciba.CIBASupportProxy;
import org.gluu.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.gluu.oxauth.model.authorize.AuthorizeRequestParam;
import org.gluu.oxauth.model.ciba.PushErrorResponseType;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.util.RedirectUri;
import org.gluu.oxauth.util.ServerUtil;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;

import javax.ejb.Stateless;
import javax.faces.application.FacesMessage;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author Yuriy Movchan
 * @author Javier Rojas Blum
 * @version May 9, 2020
 */
@Stateless
@Named
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
    private CIBASupportProxy cibaSupportProxy;

    @Inject
    private CIBAPingCallbackProxy cibaPingCallbackProxy;

    @Inject
    private CIBAPushErrorProxy cibaPushErrorProxy;

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
            String responseType = session.getSessionAttributes().get(AuthorizeRequestParam.RESPONSE_TYPE);

            boolean persistDuringImplicitFlow = ServerUtil.isFalse(appConfiguration.getUseCacheForAllImplicitFlowObjects()) || !ResponseType.isImplicitFlow(responseType);
            if (!client.getTrustedClient() && persistDuringImplicitFlow) {
                final Set<String> scopes = Sets.newHashSet(org.gluu.oxauth.model.util.StringUtils.spaceSeparatedToList(scope));
                clientAuthorizationsService.add(user.getAttribute("inum"), client.getClientId(), scopes, client.getPersistClientAuthorizations());
            }
            session.addPermission(clientId, true);
            sessionIdService.updateSessionId(session);

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
        } catch (UnsupportedEncodingException e) {
            log.trace(e.getMessage(), e);
        }
    }

    public void permissionDenied(final SessionId session) {
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
        if (cibaSupportProxy.isCIBASupported() && sessionAttribute.containsKey(AuthorizeRequestParam.AUTH_REQ_ID)) {
            CIBAGrant cibaGrant = authorizationGrantList.getCIBAGrant(sessionAttribute.get(AuthorizeRequestParam.AUTH_REQ_ID));

            if (cibaGrant != null  && cibaGrant.getClient() != null) {
                switch (cibaGrant.getClient().getBackchannelTokenDeliveryMode()) {
                    case PING:
                        cibaGrant.setUserAuthorization(CIBAGrantUserAuthorization.AUTHORIZATION_DENIED);
                        cibaGrant.setTokensDelivered(false);
                        cibaGrant.save();

                        cibaPingCallbackProxy.pingCallback(
                                cibaGrant.getCIBAAuthenticationRequestId().getCode(),
                                cibaGrant.getClient().getBackchannelClientNotificationEndpoint(),
                                cibaGrant.getClientNotificationToken()
                        );
                        break;
                    case PUSH:
                        cibaPushErrorProxy.pushError(
                                cibaGrant.getCIBAAuthenticationRequestId().getCode(),
                                cibaGrant.getClient().getBackchannelClientNotificationEndpoint(),
                                cibaGrant.getClientNotificationToken(),
                                PushErrorResponseType.ACCESS_DENIED,
                                "The end-user denied the authorization request.");
                        break;
                }
            }
        }

        facesService.redirectToExternalURL(redirectUri.toString());
    }

    private void authenticationFailedSessionInvalid() {
        facesMessages.add(FacesMessage.SEVERITY_ERROR, "login.errorSessionInvalidMessage");
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
}
