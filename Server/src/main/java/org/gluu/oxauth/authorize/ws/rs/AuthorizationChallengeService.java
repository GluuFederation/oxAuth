package org.gluu.oxauth.authorize.ws.rs;

import com.google.common.collect.Maps;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.audit.ApplicationAuditLogger;
import org.gluu.oxauth.model.authorize.AuthorizationChallengeResponse;
import org.gluu.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.gluu.oxauth.model.authorize.ScopeChecker;
import org.gluu.oxauth.model.common.AuthorizationCodeGrant;
import org.gluu.oxauth.model.common.AuthorizationGrantList;
import org.gluu.oxauth.model.common.ExecutionContext;
import org.gluu.oxauth.model.common.User;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.binding.TokenBindingMessage;
import org.gluu.oxauth.model.crypto.binding.TokenBindingParseException;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.AuthorizationChallengeSession;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.security.Identity;
import org.gluu.oxauth.service.CookieService;
import org.gluu.oxauth.service.RequestParameterService;
import org.gluu.oxauth.service.SessionIdService;
import org.gluu.oxauth.service.external.ExternalAuthorizationChallengeService;
import org.gluu.oxauth.util.ServerUtil;
import org.slf4j.Logger;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import static org.apache.commons.lang3.BooleanUtils.isFalse;

/**
 * @author Yuriy Z
 */
@RequestScoped
@Named
public class AuthorizationChallengeService {

    @Inject
    private Logger log;

    @Inject
    private AuthzRequestService authzRequestService;

    @Inject
    private ApplicationAuditLogger applicationAuditLogger;

    @Inject
    private AuthorizeRestWebServiceValidator authorizeRestWebServiceValidator;

    @Inject
    private ScopeChecker scopeChecker;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Inject
    private AuthorizationChallengeValidator authorizationChallengeValidator;

    @Inject
    private ExternalAuthorizationChallengeService externalAuthorizationChallengeService;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private AuthorizationChallengeSessionService authorizationChallengeSessionService;

    @Inject
    private Identity identity;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private RequestParameterService requestParameterService;

    @Inject
    private CookieService cookieService;

    public Response requestAuthorization(AuthzRequest authzRequest) {
        log.debug("Attempting to request authz challenge: {}", authzRequest);

        authzRequestService.createOauth2AuditLog(authzRequest);

        try {
            return authorize(authzRequest);
        } catch (WebApplicationException e) {
            if (log.isErrorEnabled() && AuthzRequestService.canLogWebApplicationException(e))
                log.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        } finally {
            applicationAuditLogger.sendMessage(authzRequest.getAuditLog());
        }

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()).build();
    }

    public void prepareAuthzRequest(AuthzRequest authzRequest) {
        authzRequest.setScope(ServerUtil.urlDecode(authzRequest.getScope()));

        if (StringUtils.isNotBlank(authzRequest.getAuthorizationChallengeSession())) {
            final AuthorizationChallengeSession authzChallengeSession = authorizationChallengeSessionService.getAuthorizationChallengeSession(authzRequest.getAuthorizationChallengeSession());

            authzRequest.setAuthorizationChallengeSessionObject(authzChallengeSession);
            if (authzChallengeSession != null) {
                final Map<String, String> authzChallengeSessionAttributes = authzChallengeSession.getAttributes().getAttributes();

                final String clientId = authzChallengeSessionAttributes.get("client_id");
                if (StringUtils.isNotBlank(clientId) && StringUtils.isBlank(authzRequest.getClientId())) {
                    authzRequest.setClientId(clientId);
                }

                String acrValues = authzChallengeSession.getAttributes().getAcrValues();
                if (StringUtils.isBlank(acrValues)) {
                    acrValues = authzChallengeSessionAttributes.get("acr_values");
                }
                if (StringUtils.isNotBlank(acrValues) && StringUtils.isBlank(authzRequest.getAcrValues())) {
                    authzRequest.setAcrValues(acrValues);
                }
            }
        }
    }

    public Response authorize(AuthzRequest authzRequest) throws IOException, TokenBindingParseException {
        final String state = authzRequest.getState();
        final String tokenBindingHeader = authzRequest.getHttpRequest().getHeader("Sec-Token-Binding");

        prepareAuthzRequest(authzRequest);

        SessionId sessionUser = identity.getSessionId();
        User user = sessionIdService.getUser(sessionUser);

        final Client client = authorizeRestWebServiceValidator.validateClient(authzRequest);
        authorizationChallengeValidator.validateGrantType(client, state);
        authorizationChallengeValidator.validateAccess(client);
        Set<String> scopes = scopeChecker.checkScopesPolicy(client, authzRequest.getScope());

        final ExecutionContext executionContext = ExecutionContext.of(authzRequest);
        executionContext.setSessionId(sessionUser);

        if (user == null) {
            log.trace("Executing external authentication challenge");

            final boolean ok = externalAuthorizationChallengeService.externalAuthorize(executionContext);
            if (!ok) {
                log.debug("Not allowed by authorization challenge script, client_id {}.", client.getClientId());
                throw new WebApplicationException(errorResponseFactory
                        .newErrorResponse(Response.Status.BAD_REQUEST)
                        .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.ACCESS_DENIED, state, "No allowed by authorization challenge script."))
                        .build());
            }

            user = executionContext.getUser() != null ? executionContext.getUser() : new User();

            // generate session if not exist and if allowed by config (or if session is prepared by script)
            if (sessionUser == null || executionContext.getAuthorizationChallengeSessionId() != null) {
                sessionUser = generateAuthenticateSessionWithCookieIfNeeded(authzRequest, user, executionContext.getAuthorizationChallengeSessionId());
            }
        }

        String grantAcr = executionContext.getScript() != null ? executionContext.getScript().getName() : authzRequest.getAcrValues();

        AuthorizationCodeGrant authorizationGrant = authorizationGrantList.createAuthorizationCodeGrant(user, client, new Date());
        authorizationGrant.setNonce(authzRequest.getNonce());
        authorizationGrant.setJwtAuthorizationRequest(authzRequest.getJwtRequest());
        authorizationGrant.setTokenBindingHash(TokenBindingMessage.getTokenBindingIdHashFromTokenBindingMessage(tokenBindingHeader, client.getIdTokenTokenBindingCnf()));
        authorizationGrant.setScopes(scopes);
        authorizationGrant.setCodeChallenge(authzRequest.getCodeChallenge());
        authorizationGrant.setCodeChallengeMethod(authzRequest.getCodeChallengeMethod());
        authorizationGrant.setClaims(authzRequest.getClaims());
        authorizationGrant.setSessionDn(sessionUser != null ? sessionUser.getDn() : "no_session_for_authorization_challenge"); // no need for session as at Authorization Endpoint
        authorizationGrant.setAcrValues(grantAcr);
        authorizationGrant.save();

        String authorizationCode = authorizationGrant.getAuthorizationCode().getCode();

        return createSuccessfulResponse(authorizationCode);
    }

    private SessionId generateAuthenticateSessionWithCookieIfNeeded(AuthzRequest authzRequest, User user, SessionId scriptGeneratedSession) {
        if (user == null) {
            log.trace("Skip session_id generation because user is null");
            return null;
        }

        if (isFalse(appConfiguration.getAuthorizationChallengeShouldGenerateSession())) {
            log.trace("Skip session_id generation because it's not allowed by AS configuration ('authorizationChallengeShouldGenerateSession=false')");
            return null;
        }

        if (scriptGeneratedSession != null) {
            log.trace("Authorization Challenge script generated session: {}.", scriptGeneratedSession.getId());
            cookieService.createSessionIdCookie(scriptGeneratedSession, authzRequest.getHttpRequest(), authzRequest.getHttpResponse(), false);
            log.trace("Created cookie for authorization Challenge script generated session: {}.", scriptGeneratedSession.getId());
            return scriptGeneratedSession;
        }

        Map<String, String> genericRequestMap = AuthorizeRestWebServiceImpl.getGenericRequestMap(authzRequest.getHttpRequest());

        Map<String, String> parameterMap = Maps.newHashMap(genericRequestMap);
        Map<String, String> requestParameterMap = requestParameterService.getAllowedParameters(parameterMap);

        SessionId sessionUser = sessionIdService.generateAuthenticatedSessionId(authzRequest.getHttpRequest(), user.getDn(), authzRequest.getPrompt());
        final Set<String> sessionAttributesKeySet = sessionUser.getSessionAttributes().keySet();
        requestParameterMap.forEach((key, value) -> {
            if (!sessionAttributesKeySet.contains(key)) {
                sessionUser.getSessionAttributes().put(key, value);
            }
        });

        cookieService.createSessionIdCookie(sessionUser, authzRequest.getHttpRequest(), authzRequest.getHttpResponse(), false);
        sessionIdService.updateSessionId(sessionUser);
        log.trace("Session updated with {}", sessionUser);

        return sessionUser;
    }

    public Response createSuccessfulResponse(String authorizationCode) throws IOException {
        AuthorizationChallengeResponse response = new AuthorizationChallengeResponse();
        response.setAuthorizationCode(authorizationCode);

        return Response.status(Response.Status.OK)
                .entity(ServerUtil.asJson(response))
                .cacheControl(ServerUtil.cacheControl(true))
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
