/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.token;

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.gluu.model.GluuAttribute;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.model.custom.script.type.auth.PersonAuthenticationType;
import org.gluu.oxauth.claims.Audience;
import org.gluu.oxauth.model.authorize.Claim;
import org.gluu.oxauth.model.authorize.JwtAuthorizationRequest;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.exception.InvalidClaimException;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.jwt.JwtSubClaimObject;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.service.AttributeService;
import org.gluu.oxauth.service.ScopeService;
import org.gluu.oxauth.service.SessionIdService;
import org.gluu.oxauth.service.date.DateFormatterService;
import org.gluu.oxauth.service.external.ExternalAuthenticationService;
import org.gluu.oxauth.service.external.ExternalDynamicScopeService;
import org.gluu.oxauth.service.external.ExternalUpdateTokenService;
import org.gluu.oxauth.service.external.context.DynamicScopeExternalContext;
import org.gluu.oxauth.service.external.context.ExternalUpdateTokenContext;
import org.json.JSONObject;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.Serializable;
import java.util.*;

import static org.gluu.oxauth.model.common.ScopeType.DYNAMIC;

/**
 * JSON Web Token (JWT) is a compact token format intended for space constrained
 * environments such as HTTP Authorization headers and URI query parameters.
 * JWTs encode claims to be transmitted as a JSON object (as defined in RFC
 * 4627) that is base64url encoded and digitally signed. Signing is accomplished
 * using a JSON Web Signature (JWS). JWTs may also be optionally encrypted using
 * JSON Web Encryption (JWE).
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @author Yuriy Zabrovarnyy
 * @version 12 Feb, 2020
 */
@ApplicationScoped
public class IdTokenFactory {

    @Inject
    private Logger log;

    @Inject
    private ExternalDynamicScopeService externalDynamicScopeService;

    @Inject
    private ExternalAuthenticationService externalAuthenticationService;

    @Inject
    private ScopeService scopeService;

    @Inject
    private AttributeService attributeService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private JwrService jwrService;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private DateFormatterService dateFormatterService;

    @Inject
    private ExternalUpdateTokenService externalUpdateTokenService;

    private void setAmrClaim(JsonWebResponse jwt, String acrValues) {
        List<String> amrList = Lists.newArrayList();

        CustomScriptConfiguration script = externalAuthenticationService.getCustomScriptConfigurationByName(acrValues);
        if (script != null) {
            amrList.add(Integer.toString(script.getLevel()));

            PersonAuthenticationType externalAuthenticator = (PersonAuthenticationType) script.getExternalType();
            int apiVersion = externalAuthenticator.getApiVersion();

            if (apiVersion > 3) {
                Map<String, String> authenticationMethodClaimsOrNull = externalAuthenticator.getAuthenticationMethodClaims(script.getConfigurationAttributes());
                if (authenticationMethodClaimsOrNull != null) {
                    for (String key : authenticationMethodClaimsOrNull.keySet()) {
                        amrList.add(key + ":" + authenticationMethodClaimsOrNull.get(key));
                    }
                }
            }
        }

        jwt.getClaims().setClaim(JwtClaimName.AUTHENTICATION_METHOD_REFERENCES, amrList);
    }

    private void fillClaims(JsonWebResponse jwr,
                            IAuthorizationGrant authorizationGrant, String nonce,
                            AuthorizationCode authorizationCode, AccessToken accessToken, RefreshToken refreshToken,
                            String state, Set<String> scopes, boolean includeIdTokenClaims,
                            Function<JsonWebResponse, Void> preProcessing, Function<JsonWebResponse, Void> postProcessing,
                            ExecutionContext executionContext) throws Exception {

        final Client client = authorizationGrant.getClient();
        jwr.getClaims().setIssuer(appConfiguration.getIssuer());
        Audience.setAudience(jwr.getClaims(), client);

        int lifeTime = appConfiguration.getIdTokenLifetime();
        if (client.getAttributes().getIdTokenLifetime() != null) {
            lifeTime = client.getAttributes().getIdTokenLifetime();
            log.trace("Override id token lifetime with value from client: {}", client.getClientId());
        }

        int lifetimeFromScript = externalUpdateTokenService.getIdTokenLifetimeInSeconds(ExternalUpdateTokenContext.of(executionContext));
        if (lifetimeFromScript > 0) {
            lifeTime = lifetimeFromScript;
            log.trace("Override id token lifetime with value from script: {}", lifetimeFromScript);
        }

        Calendar calendar = Calendar.getInstance();
        Date issuedAt = calendar.getTime();
        calendar.add(Calendar.SECOND, lifeTime);
        Date expiration = calendar.getTime();

        jwr.getClaims().setExpirationTime(expiration);
        jwr.getClaims().setIssuedAt(issuedAt);
        jwr.setClaim("code", UUID.randomUUID().toString());

        if (preProcessing != null) {
            preProcessing.apply(jwr);
        }
        final SessionId session = sessionIdService.getSessionByDn(authorizationGrant.getSessionDn(), true);
        if (session != null) {
            jwr.setClaim("sid", session.getOutsideSid());
        }

        if (authorizationGrant.getAcrValues() != null) {
            jwr.setClaim(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE, authorizationGrant.getAcrValues());
            setAmrClaim(jwr, authorizationGrant.getAcrValues());
        }
        if (StringUtils.isNotBlank(nonce)) {
            jwr.setClaim(JwtClaimName.NONCE, nonce);
        }
        if (authorizationGrant.getAuthenticationTime() != null) {
            jwr.getClaims().setClaim(JwtClaimName.AUTHENTICATION_TIME, authorizationGrant.getAuthenticationTime());
        }
        if (authorizationCode != null) {
            String codeHash = AbstractToken.getHash(authorizationCode.getCode(), jwr.getHeader().getSignatureAlgorithm());
            jwr.setClaim(JwtClaimName.CODE_HASH, codeHash);
        }
        if (accessToken != null) {
            String accessTokenHash = AbstractToken.getHash(accessToken.getCode(), jwr.getHeader().getSignatureAlgorithm());
            jwr.setClaim(JwtClaimName.ACCESS_TOKEN_HASH, accessTokenHash);
        }
        if (Strings.isNotBlank(state)) {
            String stateHash = AbstractToken.getHash(state, jwr.getHeader().getSignatureAlgorithm());
            jwr.setClaim(JwtClaimName.STATE_HASH, stateHash);
        }
        if (authorizationGrant.getGrantType() != null) {
            jwr.setClaim("grant", authorizationGrant.getGrantType().getValue());
        }
        jwr.setClaim(JwtClaimName.OX_OPENID_CONNECT_VERSION, appConfiguration.getOxOpenIdConnectVersion());

        User user = authorizationGrant.getUser();
        List<Scope> dynamicScopes = new ArrayList<>();
        if (includeIdTokenClaims && client.isIncludeClaimsInIdToken()) {
            for (String scopeName : scopes) {
                Scope scope = scopeService.getScopeById(scopeName);
                if (scope == null) {
                    continue;
                }

                if (DYNAMIC == scope.getScopeType()) {
                    dynamicScopes.add(scope);
                    continue;
                }

                Map<String, Object> claims = scopeService.getClaims(user, scope);

                if (Boolean.TRUE.equals(scope.isOxAuthGroupClaims())) {
                    JwtSubClaimObject groupClaim = new JwtSubClaimObject();
                    groupClaim.setName(scope.getId());
                    for (Map.Entry<String, Object> entry : claims.entrySet()) {
                        String key = entry.getKey();
                        Object value = entry.getValue();

                        if (value instanceof List) {
                            groupClaim.setClaim(key, (List) value);
                        } else {
                            groupClaim.setClaim(key, (String) value);
                        }
                    }

                    jwr.getClaims().setClaim(scope.getId(), groupClaim);
                } else {
                    for (Map.Entry<String, Object> entry : claims.entrySet()) {
                        String key = entry.getKey();
                        Object value = entry.getValue();
                        log.info("IdToken Factory called: {}", value);

                        if (value instanceof List) {
                            jwr.getClaims().setClaim(key, (List) value);
                        } else if (value instanceof Boolean) {
                            jwr.getClaims().setClaim(key, (Boolean) value);
                        } else if (value instanceof Date) {
                            Serializable formattedValue = dateFormatterService.formatClaim((Date) value, key);
                            jwr.getClaims().setClaimObject(key, formattedValue, true);
                        } else {
                            jwr.setClaim(key, (String) value);
                        }
                    }
                }

                jwr.getClaims().setSubjectIdentifier(authorizationGrant.getUser().getAttribute("inum"));
            }
        }

        setClaimsFromJwtAuthorizationRequest(jwr, authorizationGrant, scopes);
        setClaimsFromRequestedClaims(((AuthorizationGrant) authorizationGrant).getClaims(), jwr, user);
        jwrService.setSubjectIdentifier(jwr, authorizationGrant);

        if ((dynamicScopes.size() > 0) && externalDynamicScopeService.isEnabled()) {
            final UnmodifiableAuthorizationGrant unmodifiableAuthorizationGrant = new UnmodifiableAuthorizationGrant(authorizationGrant);
            DynamicScopeExternalContext dynamicScopeContext = new DynamicScopeExternalContext(dynamicScopes, jwr, unmodifiableAuthorizationGrant);
            externalDynamicScopeService.executeExternalUpdateMethods(dynamicScopeContext);
        }

        processCiba(jwr, authorizationGrant, refreshToken);

        if (postProcessing != null) {
        	postProcessing.apply(jwr);
        }
    }

    private void setClaimsFromRequestedClaims(String requestedClaims, JsonWebResponse jwr, User user)
            throws InvalidClaimException {
        if (requestedClaims != null) {
            JSONObject claimsObj = new JSONObject(requestedClaims);
            if (claimsObj.has("id_token")) {
                JSONObject idTokenObj = claimsObj.getJSONObject("id_token");
                for (Iterator<String> it = idTokenObj.keys(); it.hasNext(); ) {
                    String claimName = it.next();
                    GluuAttribute gluuAttribute = attributeService.getByClaimName(claimName);

                    if (gluuAttribute != null) {
                        String ldapClaimName = gluuAttribute.getName();

                        Object attribute = user.getAttribute(ldapClaimName, false, gluuAttribute.getOxMultiValuedAttribute());

                        if (attribute instanceof List) {
                            jwr.getClaims().setClaim(claimName, (List) attribute);
                        } else if (attribute instanceof Boolean) {
                            jwr.getClaims().setClaim(claimName, (Boolean) attribute);
                        } else if (attribute instanceof Date) {
                            Serializable formattedValue = dateFormatterService.formatClaim((Date) attribute, claimName);
                            jwr.getClaims().setClaimObject(claimName, formattedValue, true);
                        } else {
                            jwr.setClaim(claimName, (String) attribute);
                        }
                    }
                }
            }
        }
    }

    private void processCiba(JsonWebResponse jwr, IAuthorizationGrant authorizationGrant, RefreshToken refreshToken) {
        if (!(authorizationGrant instanceof CIBAGrant)) {
            return;
        }

        String refreshTokenHash = AbstractToken.getHash(refreshToken.getCode(), null);
        jwr.setClaim(JwtClaimName.REFRESH_TOKEN_HASH, refreshTokenHash);

        CIBAGrant cibaGrant = (CIBAGrant) authorizationGrant;
        jwr.setClaim(JwtClaimName.AUTH_REQ_ID, cibaGrant.getAuthReqId());
    }

    private void setClaimsFromJwtAuthorizationRequest(JsonWebResponse jwr, IAuthorizationGrant authorizationGrant, Set<String> scopes) throws InvalidClaimException {
        final JwtAuthorizationRequest requestObject = authorizationGrant.getJwtAuthorizationRequest();
        if (requestObject == null || requestObject.getIdTokenMember() == null) {
            return;
        }

        for (Claim claim : requestObject.getIdTokenMember().getClaims()) {
            boolean optional = true; // ClaimValueType.OPTIONAL.equals(claim.getClaimValue().getClaimValueType());
            GluuAttribute gluuAttribute = attributeService.getByClaimName(claim.getName());

            if (gluuAttribute == null) {
                continue;
            }

            Client client = authorizationGrant.getClient();

            if (validateRequesteClaim(gluuAttribute, client.getClaims(), scopes)) {
                String ldapClaimName = gluuAttribute.getName();
                Object attribute = authorizationGrant.getUser().getAttribute(ldapClaimName, optional, gluuAttribute.getOxMultiValuedAttribute());
                jwr.getClaims().setClaimFromJsonObject(claim.getName(), attribute);
            }
        }
    }

    public JsonWebResponse createJwr(
            IAuthorizationGrant grant, String nonce,
            AuthorizationCode authorizationCode, AccessToken accessToken, RefreshToken refreshToken,
            String state, Set<String> scopes, boolean includeIdTokenClaims,
            Function<JsonWebResponse, Void> preProcessing, Function<JsonWebResponse, Void> postProcessing,
            ExecutionContext executionContext) throws Exception {

        final Client client = grant.getClient();

        JsonWebResponse jwr = jwrService.createJwr(client);
        fillClaims(jwr, grant, nonce, authorizationCode, accessToken, refreshToken, state, scopes, includeIdTokenClaims, preProcessing, postProcessing, executionContext);

        if (log.isTraceEnabled())
            log.trace("Created claims for id_token, claims: " + jwr.getClaims().toJsonString());

        return jwrService.encode(jwr, client);
    }

    private boolean validateRequesteClaim(GluuAttribute gluuAttribute, String[] clientAllowedClaims, Collection<String> scopes) {
        if (gluuAttribute == null) {
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
            Scope scope = scopeService.getScopeById(scopeName);

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