package org.xdi.oxauth.bcauthorize.ws.rs;

import com.wordnik.swagger.annotations.Api;
import org.apache.logging.log4j.util.Strings;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.xdi.oxauth.audit.ApplicationAuditLogger;
import org.xdi.oxauth.ciba.CIBAAuthorizeParamsValidatorProxy;
import org.xdi.oxauth.ciba.CIBASupportProxy;
import org.xdi.oxauth.client.JwkClient;
import org.xdi.oxauth.model.audit.Action;
import org.xdi.oxauth.model.audit.OAuth2AuditLog;
import org.xdi.oxauth.model.authorize.ScopeChecker;
import org.xdi.oxauth.model.common.*;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.crypto.signature.AlgorithmFamily;
import org.xdi.oxauth.model.crypto.signature.ECDSAPublicKey;
import org.xdi.oxauth.model.crypto.signature.RSAPublicKey;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.error.DefaultErrorResponse;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.exception.InvalidJwtException;
import org.xdi.oxauth.model.jws.ECDSASigner;
import org.xdi.oxauth.model.jws.RSASigner;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.model.session.SessionClient;
import org.xdi.oxauth.security.Identity;
import org.xdi.oxauth.service.UserService;
import org.xdi.oxauth.util.ServerUtil;
import org.xdi.util.StringHelper;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Path;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.xdi.oxauth.model.ciba.BackchannelAuthenticationErrorResponseType.*;
import static org.xdi.oxauth.model.ciba.BackchannelAuthenticationResponseParam.*;

/**
 * Implementation for request backchannel authorization through REST web services.
 *
 * @author Javier Rojas Blum
 * @version May 22, 2019
 */
@Path("/")
@Api(value = "/oxauth/bc-authorize", description = "Backchannel Authorization Endpoint")
public class BackchannelAuthorizeRestWebServiceImpl implements BackchannelAuthorizeRestWebService {

    @Inject
    private Logger log;

    @Inject
    private Identity identity;

    @Inject
    private UserService userService;

    @Inject
    private ApplicationAuditLogger applicationAuditLogger;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Inject
    private ScopeChecker scopeChecker;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private CIBASupportProxy cibaSupportProxy;

    @Inject
    private CIBAAuthorizeParamsValidatorProxy cibaAuthorizeParamsValidatorProxy;

    @Override
    public Response requestBackchannelAuthorizationPost(
            String clientId, String scope, String clientNotificationToken, String acrValues, String loginHintToken,
            String idTokenHint, String loginHint, String bindingMessage, String userCode, Integer requestedExpiry,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse, SecurityContext securityContext) {
        scope = ServerUtil.urlDecode(scope); // it may be encoded

        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(httpRequest), Action.BACKCHANNEL_AUTHENTICATION);
        oAuth2AuditLog.setClientId(clientId);
        oAuth2AuditLog.setScope(scope);

        // ATTENTION : please do not add more parameter in this debug method because it will not work with Seam 2.2.2.Final ,
        // there is limit of 10 parameters (hardcoded), see: org.jboss.seam.core.Interpolator#interpolate
        log.debug("Attempting to request backchannel authorization: "
                        + "clientId = {}, scope = {}, clientNotificationToken = {}, acrValues = {}, loginHintToken = {}, "
                        + "idTokenHint = {}, loginHint = {}, bindingMessage = {}, userCode = {}, requestedExpiry = {}",
                clientId, scope, clientNotificationToken, acrValues, loginHintToken,
                idTokenHint, loginHint, bindingMessage, userCode, requestedExpiry);
        log.debug("Attempting to request backchannel authorization: "
                + "isSecure = {}", securityContext.isSecure());

        Response.ResponseBuilder builder = Response.ok();

        if (!cibaSupportProxy.isCIBASupported()) {
            builder = Response.status(Response.Status.FORBIDDEN.getStatusCode()); // 403
            builder.entity(errorResponseFactory.errorAsJson(
                    ACCESS_DENIED,
                    "The CIBA (Client Initiated Backchannel Authentication) is not enabled in the server."));
            return builder.build();
        }

        SessionClient sessionClient = identity.getSessionClient();
        Client client = null;
        if (sessionClient != null) {
            client = sessionClient.getClient();
        }

        if (client == null) {
            builder = Response.status(Response.Status.UNAUTHORIZED.getStatusCode()); // 401
            builder.entity(errorResponseFactory.getErrorAsJson(INVALID_CLIENT));
            return builder.build();
        }

        User user = null;
        try {
            if (Strings.isNotBlank(loginHint)) { // login_hint
                user = userService.getUniqueUserByAttributes(appConfiguration.getBackchannelLoginHintClaims(), loginHint);
            } else if (Strings.isNotBlank(idTokenHint)) { // id_token_hint
                AuthorizationGrant authorizationGrant = authorizationGrantList.getAuthorizationGrantByIdToken(idTokenHint);
                if (authorizationGrant == null) {
                    builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                    builder.entity(errorResponseFactory.getErrorAsJson(UNKNOWN_USER_ID));
                    return builder.build();
                }
                user = authorizationGrant.getUser();
            }
            if (Strings.isNotBlank(loginHintToken)) { // login_hint_token
                Jwt jwt = Jwt.parse(loginHintToken);

                SignatureAlgorithm algorithm = jwt.getHeader().getAlgorithm();
                String keyId = jwt.getHeader().getKeyId();

                if (algorithm == null || Strings.isBlank(keyId)) {
                    builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                    builder.entity(errorResponseFactory.getErrorAsJson(UNKNOWN_USER_ID));
                    return builder.build();
                }

                boolean validSignature = false;
                if (algorithm.getFamily() == AlgorithmFamily.RSA) {
                    RSAPublicKey publicKey = JwkClient.getRSAPublicKey(client.getJwksUri(), keyId);
                    RSASigner rsaSigner = new RSASigner(algorithm, publicKey);
                    validSignature = rsaSigner.validate(jwt);
                } else if (algorithm.getFamily() == AlgorithmFamily.EC) {
                    ECDSAPublicKey publicKey = JwkClient.getECDSAPublicKey(client.getJwksUri(), keyId);
                    ECDSASigner ecdsaSigner = new ECDSASigner(algorithm, publicKey);
                    validSignature = ecdsaSigner.validate(jwt);
                }
                if (!validSignature) {
                    builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                    builder.entity(errorResponseFactory.getErrorAsJson(UNKNOWN_USER_ID));
                    return builder.build();
                }

                JSONObject subject = jwt.getClaims().getClaimAsJSON("subject");
                if (subject == null || !subject.has("subject_type") || !subject.has(subject.getString("subject_type"))) {
                    builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                    builder.entity(errorResponseFactory.getErrorAsJson(UNKNOWN_USER_ID));
                    return builder.build();
                }

                String subjectTypeKey = subject.getString("subject_type");
                String subjectTypeValue = subject.getString(subjectTypeKey);

                user = userService.getUniqueUserByAttributes(appConfiguration.getBackchannelLoginHintClaims(), subjectTypeValue);
            }
        } catch (InvalidJwtException e) {
            log.error(e.getMessage(), e);
        } catch (JSONException e) {
            log.error(e.getMessage(), e);
        }
        if (user == null) {
            builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
            builder.entity(errorResponseFactory.getErrorAsJson(UNKNOWN_USER_ID));
            return builder.build();
        }

        List<String> scopeList = new ArrayList<String>();
        if (StringHelper.isNotEmpty(scope)) {
            Set<String> grantedScopes = scopeChecker.checkScopesPolicy(client, scope);
            scopeList.addAll(grantedScopes);
        }

        DefaultErrorResponse cibaAuthorizeParamsValidation = cibaAuthorizeParamsValidatorProxy.validateParams(
                scopeList, clientNotificationToken, client.getBackchannelTokenDeliveryMode(),
                loginHintToken, idTokenHint, loginHint, bindingMessage, client.getBackchannelUserCodeParameter(),
                userCode);
        if (cibaAuthorizeParamsValidation != null) {
            builder = Response.status(cibaAuthorizeParamsValidation.getStatus());
            builder.entity(errorResponseFactory.errorAsJson(
                    cibaAuthorizeParamsValidation.getType(), cibaAuthorizeParamsValidation.getReason()));
            return builder.build();
        }

        try {
            int expiresIn = requestedExpiry != null ? requestedExpiry : appConfiguration.getBackchannelAuthenticationResponseExpiresIn();
            Integer interval = client.getBackchannelTokenDeliveryMode() == BackchannelTokenDeliveryMode.PUSH ?
                    null : appConfiguration.getBackchannelAuthenticationResponseInterval();

            // TODO: Validate and save client_notification_token acr_values binding_message user_code
            CIBAGrant authorizationGrant = authorizationGrantList.createCIBAGrant(
                    user,
                    client,
                    expiresIn);
            authorizationGrant.setScopes(scopeList);
            authorizationGrant.save(); // call save after object modification!!!

            builder.entity(getJSONObject(
                    authorizationGrant.getCIBAAuthenticationRequestId().getCode(),
                    expiresIn,
                    interval).toString(4).replace("\\/", "/"));

            CacheControl cacheControl = new CacheControl();
            cacheControl.setNoTransform(false);
            cacheControl.setNoStore(true);
            builder.type(MediaType.APPLICATION_JSON_TYPE);
            builder.cacheControl(cacheControl);
        } catch (JSONException e) {
            builder = Response.status(400);
            builder.entity(errorResponseFactory.getErrorAsJson(INVALID_REQUEST));
            log.error(e.getMessage(), e);
        }

        applicationAuditLogger.sendMessage(oAuth2AuditLog);
        return builder.build();
    }

    private JSONObject getJSONObject(String authReqId, int expiresIn, Integer interval) throws JSONException {
        JSONObject responseJsonObject = new JSONObject();

        responseJsonObject.put(AUTH_REQ_ID, authReqId);
        responseJsonObject.put(EXPIRES_IN, expiresIn);

        if (interval != null) {
            responseJsonObject.put(INTERVAL, interval);
        }

        return responseJsonObject;
    }
}
