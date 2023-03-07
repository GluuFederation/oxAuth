/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.userinfo.ws.rs;

import org.gluu.model.GluuAttribute;
import org.gluu.oxauth.audit.ApplicationAuditLogger;
import org.gluu.oxauth.claims.Audience;
import org.gluu.oxauth.model.audit.Action;
import org.gluu.oxauth.model.audit.OAuth2AuditLog;
import org.gluu.oxauth.model.authorize.Claim;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.config.WebKeysConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.crypto.encryption.BlockEncryptionAlgorithm;
import org.gluu.oxauth.model.crypto.encryption.KeyEncryptionAlgorithm;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.exception.InvalidJweException;
import org.gluu.oxauth.model.jwe.Jwe;
import org.gluu.oxauth.model.jwe.JweEncrypter;
import org.gluu.oxauth.model.jwe.JweEncrypterImpl;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaims;
import org.gluu.oxauth.model.jwt.JwtSubClaimObject;
import org.gluu.oxauth.model.jwt.JwtType;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.token.JsonWebResponse;
import org.gluu.oxauth.model.userinfo.UserInfoErrorResponseType;
import org.gluu.oxauth.model.userinfo.UserInfoParamsValidator;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.*;
import org.gluu.oxauth.service.date.DateFormatterService;
import org.gluu.oxauth.service.external.ExternalDynamicScopeService;
import org.gluu.oxauth.service.external.context.DynamicScopeExternalContext;
import org.gluu.oxauth.service.token.TokenService;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.persist.exception.EntryPersistenceException;
import org.json.JSONObject;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.*;

/**
 * Provides interface for User Info REST web services
 *
 * @author Javier Rojas Blum
 * @version October 14, 2019
 */
@Path("/")
public class UserInfoRestWebServiceImpl implements UserInfoRestWebService {

    @Inject
    private Logger log;

    @Inject
    private ApplicationAuditLogger applicationAuditLogger;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Inject
    private ClientService clientService;

    @Inject
    private ScopeService scopeService;

    @Inject
    private AttributeService attributeService;

    @Inject
    private UserService userService;

    @Inject
    private ExternalDynamicScopeService externalDynamicScopeService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private WebKeysConfiguration webKeysConfiguration;

    @Inject
    private AbstractCryptoProvider cryptoProvider;

    @Inject
    private TokenService tokenService;

    @Inject
    private DateFormatterService dateFormatterService;

    @Override
    public Response requestUserInfoGet(String accessToken, String authorization, HttpServletRequest request, SecurityContext securityContext) {
        return requestUserInfo(accessToken, authorization, request, securityContext);
    }

    @Override
    public Response requestUserInfoPost(String accessToken, String authorization, HttpServletRequest request, SecurityContext securityContext) {
        return requestUserInfo(accessToken, authorization, request, securityContext);
    }

    private Response requestUserInfo(String accessToken, String authorization, HttpServletRequest request, SecurityContext securityContext) {

        if (tokenService.isBearerAuthToken(authorization)) {
            accessToken = tokenService.getBearerToken(authorization);
        }

        log.debug("Attempting to request User Info, Access token = {}, Is Secure = {}", accessToken, securityContext.isSecure());
        Response.ResponseBuilder builder = Response.ok();

        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(request), Action.USER_INFO);

        try {
            if (!UserInfoParamsValidator.validateParams(accessToken)) {
                return response(400, UserInfoErrorResponseType.INVALID_REQUEST, "access token is not valid.");
            }

            AuthorizationGrant authorizationGrant = authorizationGrantList.getAuthorizationGrantByAccessToken(accessToken);

            if (authorizationGrant == null) {
                log.trace("Failed to find authorization grant by access_token: " + accessToken);
                return response(401, UserInfoErrorResponseType.INVALID_TOKEN);
            }
            oAuth2AuditLog.updateOAuth2AuditLog(authorizationGrant, false);

            final AbstractToken accessTokenObject = authorizationGrant.getAccessToken(accessToken);
            if (accessTokenObject == null || !accessTokenObject.isValid()) {
                log.trace("Invalid access token object, access_token: {}, isNull: {}, isValid: {}", accessToken, accessTokenObject == null, false);
                return response(401, UserInfoErrorResponseType.INVALID_TOKEN);
            }

            if (authorizationGrant.getAuthorizationGrantType() == AuthorizationGrantType.CLIENT_CREDENTIALS) {
                return response(403, UserInfoErrorResponseType.INSUFFICIENT_SCOPE, "Grant object has client_credentials grant_type which is not valid.");
            }
            if (appConfiguration.getOpenidScopeBackwardCompatibility()
                    && !authorizationGrant.getScopes().contains(DefaultScope.OPEN_ID.toString())
                    && !authorizationGrant.getScopes().contains(DefaultScope.PROFILE.toString())) {
                return response(403, UserInfoErrorResponseType.INSUFFICIENT_SCOPE, "Both openid and profile scopes are not present.");
            }
            if (!appConfiguration.getOpenidScopeBackwardCompatibility() && !authorizationGrant.getScopes().contains(DefaultScope.OPEN_ID.toString())) {
                return response(403, UserInfoErrorResponseType.INSUFFICIENT_SCOPE, "Missed openid scope.");
            }

            oAuth2AuditLog.updateOAuth2AuditLog(authorizationGrant, true);

            builder.cacheControl(ServerUtil.cacheControlWithNoStoreTransformAndPrivate());
            builder.header("Pragma", "no-cache");

            User currentUser = authorizationGrant.getUser();
            try {
                currentUser = userService.getUserByDn(authorizationGrant.getUserDn());
            } catch (EntryPersistenceException ex) {
                log.warn("Failed to reload user entry: '{}'", authorizationGrant.getUserDn());
            }

            if (authorizationGrant.getClient() != null
                    && authorizationGrant.getClient().getUserInfoEncryptedResponseAlg() != null
                    && authorizationGrant.getClient().getUserInfoEncryptedResponseEnc() != null) {
                KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.fromName(authorizationGrant.getClient().getUserInfoEncryptedResponseAlg());
                BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.fromName(authorizationGrant.getClient().getUserInfoEncryptedResponseEnc());
                builder.type("application/jwt");
                builder.entity(getJweResponse(
                        keyEncryptionAlgorithm,
                        blockEncryptionAlgorithm,
                        currentUser,
                        authorizationGrant,
                        authorizationGrant.getScopes()));
            } else if (authorizationGrant.getClient() != null
                    && authorizationGrant.getClient().getUserInfoSignedResponseAlg() != null) {
                SignatureAlgorithm algorithm = SignatureAlgorithm.fromString(authorizationGrant.getClient().getUserInfoSignedResponseAlg());
                builder.type("application/jwt");
                builder.entity(getJwtResponse(algorithm,
                        currentUser,
                        authorizationGrant,
                        authorizationGrant.getScopes()));
            } else {
                builder.type((MediaType.APPLICATION_JSON + ";charset=UTF-8"));
                builder.entity(getJSonResponse(currentUser,
                        authorizationGrant,
                        authorizationGrant.getScopes()));
            }
            return builder.build();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()).build(); // 500
        } finally {
            applicationAuditLogger.sendMessage(oAuth2AuditLog);
        }
    }

    private Response response(int status, UserInfoErrorResponseType errorResponseType) {
        return response(status, errorResponseType, "");
    }

    private Response response(int status, UserInfoErrorResponseType errorResponseType, String reason) {
        return Response
                .status(status)
                .entity(errorResponseFactory.errorAsJson(errorResponseType, reason))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .cacheControl(ServerUtil.cacheControlWithNoStoreTransformAndPrivate())
                .build();
    }

    private String getJwtResponse(SignatureAlgorithm signatureAlgorithm, User user, AuthorizationGrant authorizationGrant,
                                  Collection<String> scopes) throws Exception {
        log.trace("Building JWT reponse with next scopes {0} for user {1} and user custom attributes {0}", scopes, user.getUserId(), user.getCustomAttributes());

        Jwt jwt = new Jwt();

        // Header
        jwt.getHeader().setType(JwtType.JWT);
        jwt.getHeader().setAlgorithm(signatureAlgorithm);

        String keyId = new ServerCryptoProvider(cryptoProvider).getKeyId(webKeysConfiguration, Algorithm.fromString(signatureAlgorithm.getName()), Use.SIGNATURE);
        if (keyId != null) {
            jwt.getHeader().setKeyId(keyId);
        }

        // Claims
        jwt.setClaims(createJwtClaims(user, authorizationGrant, scopes));

        // Signature
        String sharedSecret = clientService.decryptSecret(authorizationGrant.getClient().getClientSecret());
        String signature = cryptoProvider.sign(jwt.getSigningInput(), jwt.getHeader().getKeyId(), sharedSecret, signatureAlgorithm);
        jwt.setEncodedSignature(signature);

        return jwt.toString();
    }

    private JwtClaims createJwtClaims(User user, AuthorizationGrant authorizationGrant, Collection<String> scopes) throws Exception {
        String claimsString = getJSonResponse(user, authorizationGrant, scopes);
        JwtClaims claims = new JwtClaims(new JSONObject(claimsString));

        claims.setIssuer(appConfiguration.getIssuer());
        Audience.setAudience(claims, authorizationGrant.getClient());
        return claims;
    }

    public String getJweResponse(
            KeyEncryptionAlgorithm keyEncryptionAlgorithm, BlockEncryptionAlgorithm blockEncryptionAlgorithm,
            User user, AuthorizationGrant authorizationGrant, Collection<String> scopes) throws Exception {
        log.trace("Building JWE reponse with next scopes {0} for user {1} and user custom attributes {0}", scopes, user.getUserId(), user.getCustomAttributes());

        Jwe jwe = new Jwe();

        // Header
        jwe.getHeader().setType(JwtType.JWT);
        jwe.getHeader().setAlgorithm(keyEncryptionAlgorithm);
        jwe.getHeader().setEncryptionMethod(blockEncryptionAlgorithm);

        // Claims
        jwe.setClaims(createJwtClaims(user, authorizationGrant, scopes));

        // Encryption
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA_OAEP
                || keyEncryptionAlgorithm == KeyEncryptionAlgorithm.RSA1_5) {
            JSONObject jsonWebKeys = ServerUtil.getJwks(authorizationGrant.getClient());
            String keyId = new ServerCryptoProvider(cryptoProvider).getKeyId(JSONWebKeySet.fromJSONObject(jsonWebKeys),
                    Algorithm.fromString(keyEncryptionAlgorithm.getName()),
                    Use.ENCRYPTION);
            PublicKey publicKey = cryptoProvider.getPublicKey(keyId, jsonWebKeys, null);

            if (publicKey != null) {
                JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, publicKey);
                jwe = jweEncrypter.encrypt(jwe);
            } else {
                throw new InvalidJweException("The public key is not valid");
            }
        } else if (keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A128KW
                || keyEncryptionAlgorithm == KeyEncryptionAlgorithm.A256KW) {
            try {
                byte[] sharedSymmetricKey = clientService.decryptSecret(authorizationGrant.getClient().getClientSecret()).getBytes(Util.UTF8_STRING_ENCODING);
                JweEncrypter jweEncrypter = new JweEncrypterImpl(keyEncryptionAlgorithm, blockEncryptionAlgorithm, sharedSymmetricKey);
                jwe = jweEncrypter.encrypt(jwe);
            } catch (Exception e) {
                throw new InvalidJweException(e);
            }
        }

        return jwe.toString();
    }

    /**
     * Builds a JSon String with the response parameters.
     */
    public String getJSonResponse(User user, AuthorizationGrant authorizationGrant, Collection<String> scopes)
            throws Exception {
        log.trace("Building JSON reponse with next scopes {0} for user {1} and user custom attributes {0}", scopes, user.getUserId(), user.getCustomAttributes());

        JsonWebResponse jsonWebResponse = new JsonWebResponse();

        // Claims
        List<Scope> dynamicScopes = new ArrayList<Scope>();
        for (String scopeName : scopes) {
            org.oxauth.persistence.model.Scope scope = scopeService.getScopeById(scopeName);
            if ((scope != null) && (org.gluu.oxauth.model.common.ScopeType.DYNAMIC == scope.getScopeType())) {
                dynamicScopes.add(scope);
                continue;
            }

            Map<String, Object> claims = scopeService.getClaims(user, scope);
            if (claims == null) {
                continue;
            }

            if (scope != null && Boolean.TRUE.equals(scope.isOxAuthGroupClaims())) {
                JwtSubClaimObject groupClaim = new JwtSubClaimObject();
                groupClaim.setName(scope.getId());
                for (Map.Entry<String, Object> entry : claims.entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();

                    if (value instanceof List) {
                        groupClaim.setClaim(key, (List<String>) value);
                    } else {
                        groupClaim.setClaim(key, String.valueOf(value));
                    }
                }

                jsonWebResponse.getClaims().setClaim(scope.getId(), groupClaim);
            } else {
                log.info("User Info rest called: {}", claims.entrySet());
                for (Map.Entry<String, Object> entry : claims.entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();

                    if (value instanceof List) {
                        jsonWebResponse.getClaims().setClaim(key, (List<String>) value);
                    } else if (value instanceof Boolean) {
                        jsonWebResponse.getClaims().setClaim(key, (Boolean) value);
                    } else if (value instanceof Date) {
                        Serializable formattedValue = dateFormatterService.formatClaim((Date) value, key);
                        jsonWebResponse.getClaims().setClaimObject(key, formattedValue, true);
                    } else {
                        jsonWebResponse.getClaims().setClaim(key, String.valueOf(value));
                    }
                }
            }
        }

        if (authorizationGrant.getClaims() != null) {
            JSONObject claimsObj = new JSONObject(authorizationGrant.getClaims());
            if (claimsObj.has("userinfo")) {
                JSONObject userInfoObj = claimsObj.getJSONObject("userinfo");
                for (Iterator<String> it = userInfoObj.keys(); it.hasNext(); ) {
                    String claimName = it.next();
                    boolean optional = true; // ClaimValueType.OPTIONAL.equals(claim.getClaimValue().getClaimValueType());
                    GluuAttribute gluuAttribute = attributeService.getByClaimName(claimName);

                    if (gluuAttribute != null) {
                        String ldapClaimName = gluuAttribute.getName();

                        Object attribute = user.getAttribute(ldapClaimName, optional, gluuAttribute.getOxMultiValuedAttribute());
                        jsonWebResponse.getClaims().setClaimFromJsonObject(claimName, attribute);
                    }
                }
            }
        }

        if (authorizationGrant.getJwtAuthorizationRequest() != null
                && authorizationGrant.getJwtAuthorizationRequest().getUserInfoMember() != null) {
            for (Claim claim : authorizationGrant.getJwtAuthorizationRequest().getUserInfoMember().getClaims()) {
                boolean optional = true; // ClaimValueType.OPTIONAL.equals(claim.getClaimValue().getClaimValueType());
                GluuAttribute gluuAttribute = attributeService.getByClaimName(claim.getName());

                if (gluuAttribute != null) {
                    Client client = authorizationGrant.getClient();

                    if (validateRequesteClaim(gluuAttribute, client.getClaims(), scopes)) {
                        String ldapClaimName = gluuAttribute.getName();
                        Object attribute = user.getAttribute(ldapClaimName, optional, gluuAttribute.getOxMultiValuedAttribute());
                        jsonWebResponse.getClaims().setClaimFromJsonObject(claim.getName(), attribute);
                    }
                }
            }
        }

        jsonWebResponse.getClaims().setSubjectIdentifier(authorizationGrant.getSub());

        if ((dynamicScopes.size() > 0) && externalDynamicScopeService.isEnabled()) {
            final UnmodifiableAuthorizationGrant unmodifiableAuthorizationGrant = new UnmodifiableAuthorizationGrant(authorizationGrant);
            DynamicScopeExternalContext dynamicScopeContext = new DynamicScopeExternalContext(dynamicScopes, jsonWebResponse, unmodifiableAuthorizationGrant);
            externalDynamicScopeService.executeExternalUpdateMethods(dynamicScopeContext);
        }

        return jsonWebResponse.toString();
    }

    public boolean validateRequesteClaim(GluuAttribute gluuAttribute, String[] clientAllowedClaims, Collection<String> scopes) {
        if (gluuAttribute == null) {
            log.trace("gluuAttribute is null.");
            return false;
        }
        if (clientAllowedClaims != null) {
            for (String clientAllowedClaim : clientAllowedClaims) {
                if (gluuAttribute.getDn().equals(clientAllowedClaim)) {
                    return true;
                }
            }
        }

        for (String scopeName : scopes) {
            org.oxauth.persistence.model.Scope scope = scopeService.getScopeById(scopeName);

            if (scope != null && scope.getOxAuthClaims() != null) {
                for (String claimDn : scope.getOxAuthClaims()) {
                    if (gluuAttribute.getDisplayName().equals(attributeService.getAttributeByDn(claimDn).getDisplayName())) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}