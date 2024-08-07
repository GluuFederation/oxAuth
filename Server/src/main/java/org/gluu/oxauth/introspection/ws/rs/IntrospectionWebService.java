/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.introspection.ws.rs;

import com.google.common.collect.Lists;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.claims.Audience;
import org.gluu.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.config.WebKeysConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.token.JwtSigner;
import org.gluu.oxauth.model.uma.UmaScopeType;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.AttributeService;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.external.ExternalIntrospectionService;
import org.gluu.oxauth.service.external.context.ExternalIntrospectionContext;
import org.gluu.oxauth.service.token.TokenService;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.util.Pair;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import static org.apache.commons.lang3.BooleanUtils.isTrue;

/**
 * @author Yuriy Zabrovarnyy
 * @version June 30, 2018
 */
@Path("/introspection")
public class IntrospectionWebService {

    private static final Pair<AuthorizationGrant, Boolean> EMPTY = new Pair<>(null, false);

    @Inject
    private Logger log;
    @Inject
    private AppConfiguration appConfiguration;
    @Inject
    private TokenService tokenService;
    @Inject
    private ErrorResponseFactory errorResponseFactory;
    @Inject
    private AuthorizationGrantList authorizationGrantList;
    @Inject
    private ClientService clientService;
    @Inject
    private ExternalIntrospectionService externalIntrospectionService;
    @Inject
    private AttributeService attributeService;
    @Inject
    private WebKeysConfiguration webKeysConfiguration;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectGet(@HeaderParam("Authorization") String p_authorization,
                                  @QueryParam("token") String p_token,
                                  @QueryParam("token_type_hint") String tokenTypeHint,
                                  @QueryParam("response_as_jwt") String responseAsJwt,
                                  @Context HttpServletRequest httpRequest,
                                  @Context HttpServletResponse httpResponse
    ) {
        return introspect(p_authorization, p_token, tokenTypeHint, responseAsJwt, httpRequest, httpResponse);
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectPost(@HeaderParam("Authorization") String p_authorization,
                                   @FormParam("token") String p_token,
                                   @FormParam("token_type_hint") String tokenTypeHint,
                                   @FormParam("response_as_jwt") String responseAsJwt,
                                   @Context HttpServletRequest httpRequest,
                                   @Context HttpServletResponse httpResponse) {
        return introspect(p_authorization, p_token, tokenTypeHint, responseAsJwt, httpRequest, httpResponse);
    }

    private AuthorizationGrant validateAuthorization(String p_authorization, String p_token) throws IOException {
        final boolean skipAuthorization = ServerUtil.isTrue(appConfiguration.getIntrospectionSkipAuthorization());
        log.trace("skipAuthorization: {}", skipAuthorization);
        if (skipAuthorization) {
            return null;
        }

        if (StringUtils.isBlank(p_authorization)) {
            log.trace("Bad request: Authorization header or token is blank.");
            throw new WebApplicationException(Response.status(Response.Status.BAD_REQUEST).type(MediaType.APPLICATION_JSON_TYPE).entity(errorResponseFactory.errorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST, "")).build());
        }

        final Pair<AuthorizationGrant, Boolean> pair = getAuthorizationGrant(p_authorization, p_token);
        final AuthorizationGrant authorizationGrant = pair.getFirst();
        if (authorizationGrant == null) {
            log.debug("Authorization grant is null.");
            if (isTrue(pair.getSecond())) {
                log.debug("Returned {\"active\":false}.");
                throw new WebApplicationException(Response.status(Response.Status.OK)
                        .entity("{\"active\":false}")
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .build());
            }
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .entity(errorResponseFactory.errorAsJson(AuthorizeErrorResponseType.ACCESS_DENIED, "Authorization grant is null."))
                    .build());
        }

        final AbstractToken authorizationAccessToken = authorizationGrant.getAccessToken(tokenService.getToken(p_authorization));

        if ((authorizationAccessToken == null || !authorizationAccessToken.isValid()) && !pair.getSecond()) {
            log.error("Access token is not valid. Valid: " + (authorizationAccessToken != null && authorizationAccessToken.isValid()) + ", basicClientAuthentication: " + pair.getSecond());
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).type(MediaType.APPLICATION_JSON_TYPE).entity(errorResponseFactory.errorAsJson(AuthorizeErrorResponseType.ACCESS_DENIED, "Access token is not valid")).build());
        }

        if (ServerUtil.isTrue(appConfiguration.getIntrospectionAccessTokenMustHaveUmaProtectionScope()) &&
                !authorizationGrant.getScopesAsString().contains(UmaScopeType.PROTECTION.getValue())) { // #562 - make uma_protection optional
            final String reason = "access_token used to access introspection endpoint does not have uma_protection scope, however in oxauth configuration `checkUmaProtectionScopePresenceDuringIntrospection` is true";
            log.trace(reason);
            throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).entity(errorResponseFactory.errorAsJson(AuthorizeErrorResponseType.ACCESS_DENIED, reason)).type(MediaType.APPLICATION_JSON_TYPE).build());
        }
        return authorizationGrant;
    }

    private Response introspect(String p_authorization, String p_token, String tokenTypeHint, String responseAsJwt, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        try {
            log.trace("Introspect token, authorization: {}, token to introspect: {}, tokenTypeHint: {}", p_authorization, p_token, tokenTypeHint);

            AuthorizationGrant authorizationGrant = validateAuthorization(p_authorization, p_token);

            if (StringUtils.isBlank(p_token)) {
                log.trace("Bad request: Token is blank.");
                return Response.status(Response.Status.BAD_REQUEST).type(MediaType.APPLICATION_JSON_TYPE).entity(errorResponseFactory.errorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST, "")).build();
            }

            final IntrospectionResponse response = new IntrospectionResponse(false);

            final AuthorizationGrant grantOfIntrospectionToken = authorizationGrantList.getAuthorizationGrantByAccessToken(p_token);

            AbstractToken tokenToIntrospect = null;
            if (grantOfIntrospectionToken != null) {
                tokenToIntrospect = grantOfIntrospectionToken.getAccessToken(p_token);

                response.setActive(tokenToIntrospect.isValid());
                response.setExpiresAt(ServerUtil.dateToSeconds(tokenToIntrospect.getExpirationDate()));
                response.setIssuedAt(ServerUtil.dateToSeconds(tokenToIntrospect.getCreationDate()));
                response.setAcrValues(grantOfIntrospectionToken.getAcrValues());
                response.setScope(grantOfIntrospectionToken.getScopes() != null ? grantOfIntrospectionToken.getScopes() : Lists.newArrayList()); // #433
                response.setClientId(grantOfIntrospectionToken.getClientId());
                response.setSub(grantOfIntrospectionToken.getSub());
                response.setUsername(grantOfIntrospectionToken.getUserId());
                response.setIssuer(appConfiguration.getIssuer());
                response.setAudience(grantOfIntrospectionToken.getClientId());

                if (tokenToIntrospect instanceof AccessToken) {
                    AccessToken accessToken = (AccessToken) tokenToIntrospect;
                    response.setTokenType(accessToken.getTokenType() != null ? accessToken.getTokenType().getName() : TokenType.BEARER.getName());
                }
            } else {
                log.debug("Failed to find grant for access_token: " + p_token + ". Return 200 with active=false.");
            }
            JSONObject responseAsJsonObject = createResponseAsJsonObject(response, grantOfIntrospectionToken);

            ExternalIntrospectionContext context = new ExternalIntrospectionContext(authorizationGrant, httpRequest, httpResponse, appConfiguration, attributeService);
            context.setGrantOfIntrospectionToken(grantOfIntrospectionToken);
            if (externalIntrospectionService.executeExternalModifyResponse(responseAsJsonObject, context)) {
                log.trace("Successfully run extenal introspection scripts.");
            } else {
                responseAsJsonObject = createResponseAsJsonObject(response, grantOfIntrospectionToken);
                log.trace("Canceled changes made by external introspection script since method returned `false`.");
            }

            // Make scopes conform as required by spec, see #1499
            if (response.getScope()!= null && !appConfiguration.getIntrospectionResponseScopesBackwardCompatibility()) {
            	String scopes = StringUtils.join(response.getScope().toArray(), " ");
            	responseAsJsonObject.put("scope", scopes);
            }
            if (Boolean.TRUE.toString().equalsIgnoreCase(responseAsJwt)) {
                return Response.status(Response.Status.OK).entity(createResponseAsJwt(responseAsJsonObject, grantOfIntrospectionToken)).build();
            }

            final String entity = responseAsJsonObject.toString();
            if (log.isTraceEnabled()) {
                log.trace("Response entity: {}", entity);
            }
            return Response.status(Response.Status.OK).entity(entity).type(MediaType.APPLICATION_JSON_TYPE).build();

        } catch (WebApplicationException e) {
            log.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON_TYPE).build();
        }
    }

    private String createResponseAsJwt(JSONObject response, AuthorizationGrant grant) throws Exception {
        final JwtSigner jwtSigner = JwtSigner.newJwtSigner(appConfiguration, webKeysConfiguration, grant.getClient());
        final Jwt jwt = jwtSigner.newJwt();
        Audience.setAudience(jwt.getClaims(), grant.getClient());

        Iterator<String> keysIter = response.keys();
        while (keysIter.hasNext()) {
            String key = keysIter.next();
            Object value = response.opt(key);
            if (value != null) {
                try {
                    jwt.getClaims().setClaimObject(key, value, false);
                } catch (Exception e) {
                    log.error("Failed to put claims into jwt. Key: " + key + ", response: " + response.toString(), e);
                }
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("Response before signing: {}", jwt.getClaims().toJsonString());
        }
        return jwtSigner.sign().toString();
    }

    private JSONObject createResponseAsJsonObject(IntrospectionResponse response, AuthorizationGrant grantOfIntrospectionToken) throws JSONException, IOException {
        final JSONObject result = new JSONObject(ServerUtil.asJson(response));

        if (log.isTraceEnabled()) {
            log.trace("grantOfIntrospectionToken: {}, x5ts256: {}", (grantOfIntrospectionToken != null), (grantOfIntrospectionToken != null ? grantOfIntrospectionToken.getX5ts256() : ""));
        }

        if (grantOfIntrospectionToken != null && StringUtils.isNotBlank(grantOfIntrospectionToken.getX5ts256())) {
            JSONObject cnf = result.optJSONObject("cnf");
            if (cnf == null) {
                cnf = new JSONObject();
                result.put("cnf", cnf);
            }

            cnf.put("x5t#S256", grantOfIntrospectionToken.getX5ts256());
        }

        return result;
    }

    /**
     * @return we return pair of authorization grant or otherwise true - if it's basic client authentication or false if it is not
     * @throws UnsupportedEncodingException when encoding is not supported
     */
    private Pair<AuthorizationGrant, Boolean> getAuthorizationGrant(String authorization, String accessToken) throws UnsupportedEncodingException {
        AuthorizationGrant grant = tokenService.getBearerAuthorizationGrant(authorization);
        if (grant != null) {
            final String authorizationAccessToken = tokenService.getBearerToken(authorization);
            final AbstractToken accessTokenObject = grant.getAccessToken(authorizationAccessToken);
            if (accessTokenObject != null && accessTokenObject.isValid()) {
                return new Pair<>(grant, false);
            } else {
                log.error("Access token is not valid: " + authorizationAccessToken);
                return EMPTY;
            }
        }

        grant = tokenService.getBasicAuthorizationGrant(authorization);
        if (grant != null) {
            return new Pair<>(grant, false);
        }
        if (tokenService.isBasicAuthToken(authorization)) {

            String encodedCredentials = tokenService.getBasicToken(authorization);

            String token = new String(Base64.decodeBase64(encodedCredentials), StandardCharsets.UTF_8);

            int delim = token.indexOf(":");

            if (delim != -1) {
                String clientId = URLDecoder.decode(token.substring(0, delim), Util.UTF8_STRING_ENCODING);
                String password = URLDecoder.decode(token.substring(delim + 1), Util.UTF8_STRING_ENCODING);
                if (clientService.authenticate(clientId, password)) {
                    grant = authorizationGrantList.getAuthorizationGrantByAccessToken(accessToken);
                    if (isTrue(appConfiguration.getIntrospectionRestrictBasicAuthnToOwnTokens()) && grant != null && !grant.getClientId().equals(clientId)) {
                        log.trace("Failed to match grant object clientId and client id provided during authentication.");
                        return EMPTY;
                    }
                    return new Pair<>(grant, true);
                } else {
                    log.trace("Failed to perform basic authentication for client: {}", clientId);
                }
            }
        }
        return EMPTY;
    }

}
