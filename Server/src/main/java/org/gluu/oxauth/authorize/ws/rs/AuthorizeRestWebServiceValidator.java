package org.gluu.oxauth.authorize.ws.rs;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.gluu.oxauth.model.authorize.AuthorizeParamsValidator;
import org.gluu.oxauth.model.authorize.JwtAuthorizationRequest;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.DeviceAuthorizationService;
import org.gluu.oxauth.service.RedirectUriResponse;
import org.gluu.oxauth.service.RedirectionUriService;
import org.gluu.oxauth.util.RedirectUri;
import org.gluu.oxauth.util.RedirectUtil;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.persist.exception.EntryPersistenceException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

import static org.apache.commons.lang3.BooleanUtils.isTrue;
import static org.gluu.oxauth.model.ciba.BackchannelAuthenticationErrorResponseType.INVALID_REQUEST;

/**
 * @author Yuriy Zabrovarnyy
 */
@Named
public class AuthorizeRestWebServiceValidator {

    @Inject
    private Logger log;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private ClientService clientService;

    @Inject
    private RedirectionUriService redirectionUriService;

    @Inject
    private DeviceAuthorizationService deviceAuthorizationService;

    @Inject
    private AppConfiguration appConfiguration;

    public Client validateClient(String clientId, String state) {
        if (StringUtils.isBlank(clientId)) {
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.UNAUTHORIZED_CLIENT, state, "client_id is empty or blank."))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build());
        }

        try {
            final Client client = clientService.getClient(clientId);
            if (client == null) {
                throw new WebApplicationException(Response
                        .status(Response.Status.UNAUTHORIZED)
                        .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.UNAUTHORIZED_CLIENT, state, "Unable to find client."))
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build());
            }
            if (client.isDisabled()) {
                throw new WebApplicationException(Response
                        .status(Response.Status.UNAUTHORIZED)
                        .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.DISABLED_CLIENT, state, "Client is disabled."))
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build());
            }

            return client;
        } catch (EntryPersistenceException e) { // Invalid clientId
            throw new WebApplicationException(Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.UNAUTHORIZED_CLIENT, state, "Unable to find client on AS."))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build());
        }
    }

    public boolean isAuthnMaxAgeValid(Integer maxAge, SessionId sessionUser, Client client) {
        if (maxAge == null) {
            maxAge = client.getDefaultMaxAge();
        }
        if (maxAge == null) { // if not set, it's still valid
            return true;
        }

        if (maxAge == 0) { // issue #2361: allow authentication for max_age=0
            if (BooleanUtils.isTrue(appConfiguration.getDisableAuthnForMaxAgeZero())) {
                return false;
            }
            return true;
        }


        GregorianCalendar userAuthnTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        if (sessionUser.getAuthenticationTime() != null) {
            userAuthnTime.setTime(sessionUser.getAuthenticationTime());
        }

        userAuthnTime.add(Calendar.SECOND, maxAge);
        return userAuthnTime.after(ServerUtil.now());
    }

    public void validateRequestJwt(String request, String requestUri, RedirectUriResponse redirectUriResponse) {
        if (appConfiguration.getFapiCompatibility() && StringUtils.isBlank(request) && StringUtils.isBlank(requestUri)) {
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST, "request and request_uri are both not specified which is forbidden for FAPI.");
        }
        if (StringUtils.isNotBlank(request) && StringUtils.isNotBlank(requestUri)) {
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST, "Both request and request_uri are specified which is not allowed.");
        }
    }

    public void validate(List<ResponseType> responseTypes, List<Prompt> prompts, String nonce, String state, String redirectUri, HttpServletRequest httpRequest, Client client, ResponseMode responseMode) {
        if (!AuthorizeParamsValidator.validateParams(responseTypes, prompts, nonce, appConfiguration.getFapiCompatibility())) {
            if (redirectUri != null && redirectionUriService.validateRedirectionUri(client, redirectUri) != null) {
                RedirectUri redirectUriResponse = new RedirectUri(redirectUri, responseTypes, responseMode);
                redirectUriResponse.parseQueryString(errorResponseFactory.getErrorAsQueryString(
                        AuthorizeErrorResponseType.INVALID_REQUEST, state));
                throw new WebApplicationException(RedirectUtil.getRedirectResponseBuilder(redirectUriResponse, httpRequest).build());
            } else {
                throw new WebApplicationException(Response
                        .status(Response.Status.BAD_REQUEST.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST, state, "Invalid redirect uri."))
                        .build());
            }
        }
    }

    public void validateRequestObject(JwtAuthorizationRequest jwtRequest, RedirectUriResponse redirectUriResponse) {
        if (!jwtRequest.getAud().isEmpty() && !jwtRequest.getAud().contains(appConfiguration.getIssuer())) {
            log.error("Failed to match aud to AS, aud: " + jwtRequest.getAud());
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST_OBJECT);
        }

        if (!appConfiguration.getFapiCompatibility()) {
            return;
        }

        // FAPI related validation
        if (jwtRequest.getExp() == null) {
            log.error("The exp claim is not set");
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST_OBJECT);
        }
        final long expInMillis = jwtRequest.getExp() * 1000L;
        final long now = new Date().getTime();
        if (expInMillis < now) {
            log.error("Request object expired. Exp:" + expInMillis + ", now: " + now);
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST_OBJECT);
        }
        if (jwtRequest.getScopes() == null || jwtRequest.getScopes().isEmpty()) {
            log.error("Request object does not have scope claim.");
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST_OBJECT);
        }
        if (StringUtils.isBlank(jwtRequest.getNonce())) {
            log.error("Request object does not have nonce claim.");
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST_OBJECT);
        }
        if (StringUtils.isBlank(jwtRequest.getRedirectUri())) {
            log.error("Request object does not have redirect_uri claim.");
            throw redirectUriResponse.createWebException(AuthorizeErrorResponseType.INVALID_REQUEST_OBJECT);
        }
    }

    /**
     * Validates expiration, audience and scopes in the JWT request.
     * @param jwtRequest Object to be validated.
     */
    public void validateCibaRequestObject(JwtAuthorizationRequest jwtRequest, String clientId) {
        if (jwtRequest.getAud().isEmpty() || !jwtRequest.getAud().contains(appConfiguration.getIssuer())) {
            log.error("Failed to match aud to AS, aud: " + jwtRequest.getAud());
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }

        if (!appConfiguration.getFapiCompatibility()) {
            return;
        }

        // FAPI related validation
        if (jwtRequest.getExp() == null) {
            log.error("The exp claim is not set");
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        final long expInMillis = jwtRequest.getExp() * 1000L;
        final long now = new Date().getTime();
        if (expInMillis < now) {
            log.error("Request object expired. Exp:" + expInMillis + ", now: " + now);
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        if (jwtRequest.getScopes() == null || jwtRequest.getScopes().isEmpty()) {
            log.error("Request object does not have scope claim.");
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        if (StringUtils.isEmpty(jwtRequest.getIss()) || !jwtRequest.getIss().equals(clientId)) {
            log.error("Request object has a wrong iss claim, iss: " + jwtRequest.getIss());
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        if (jwtRequest.getIat() == null || jwtRequest.getIat() == 0) {
            log.error("Request object has a wrong iat claim, iat: " + jwtRequest.getIat());
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        int nowInSeconds = Math.toIntExact(System.currentTimeMillis() / 1000);
        if (jwtRequest.getNbf() == null || jwtRequest.getNbf() >  nowInSeconds
                || jwtRequest.getNbf() < nowInSeconds - appConfiguration.getCibaMaxExpirationTimeAllowedSec()) {
            log.error("Request object has a wrong nbf claim, nbf: " + jwtRequest.getNbf());
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        if (StringUtils.isEmpty(jwtRequest.getJti())) {
            log.error("Request object has a wrong jti claim, jti: " + jwtRequest.getJti());
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
        int result = (StringUtils.isNotBlank(jwtRequest.getLoginHint()) ? 1 : 0)
                + (StringUtils.isNotBlank(jwtRequest.getLoginHintToken()) ? 1 : 0)
                + (StringUtils.isNotBlank(jwtRequest.getIdTokenHint()) ? 1 : 0);
        if (result != 1) {
            log.error("Request object has too many hints or doesnt have any");
            throw new WebApplicationException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST))
                    .build());
        }
    }

    public String validateRedirectUri(@NotNull Client client, @Nullable String redirectUri, String state,
                                      String deviceAuthzUserCode, HttpServletRequest httpRequest) {
        if (StringUtils.isNotBlank(deviceAuthzUserCode)) {
            DeviceAuthorizationCacheControl deviceAuthorizationCacheControl = deviceAuthorizationService
                    .getDeviceAuthzByUserCode(deviceAuthzUserCode);
            redirectUri = deviceAuthorizationService.getDeviceAuthorizationPage(deviceAuthorizationCacheControl, client, state, httpRequest);
        } else {
            redirectUri = redirectionUriService.validateRedirectionUri(client, redirectUri);
        }
        if (StringUtils.isNotBlank(redirectUri)) {
            return redirectUri;
        }
        throw new WebApplicationException(Response
                .status(Response.Status.BAD_REQUEST)
                .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST_REDIRECT_URI, state, ""))
                .build());
    }

    public void validateRequestParameterSupported(String request, String state) {
        if (StringUtils.isBlank(request)) {
            return;
        }

        if (isTrue(appConfiguration.getRequestParameterSupported())) {
            return;
        }

        log.debug("'request' support is switched off by requestParameterSupported=false configuration property.");
        throw new WebApplicationException(Response
                .status(Response.Status.BAD_REQUEST)
                .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.REQUEST_NOT_SUPPORTED, state, "request processing is denied by AS."))
                .build());

    }

    public void validateRequestUriParameterSupported(String requestUri, String state) {
        if (StringUtils.isBlank(requestUri)) {
            return;
        }

        if (isTrue(appConfiguration.getRequestUriParameterSupported())) {
            return;
        }

        log.debug("'request_uri' support is switched off by requestUriParameterSupported=false configuration property.");
        throw new WebApplicationException(Response
                .status(Response.Status.BAD_REQUEST)
                .entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.REQUEST_URI_NOT_SUPPORTED, state, "request_uri processing is denied by AS"))
                .build());
    }
}
