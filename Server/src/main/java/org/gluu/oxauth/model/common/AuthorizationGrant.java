/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import com.google.common.base.Function;
import com.google.common.collect.Lists;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.claims.Audience;
import org.gluu.oxauth.model.authorize.JwtAuthorizationRequest;
import org.gluu.oxauth.model.config.WebKeysConfiguration;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.token.IdTokenFactory;
import org.gluu.oxauth.model.token.JsonWebResponse;
import org.gluu.oxauth.model.token.JwtSigner;
import org.gluu.oxauth.model.util.JwtUtil;
import org.gluu.oxauth.service.AttributeService;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.GrantService;
import org.gluu.oxauth.service.SectorIdentifierService;
import org.gluu.oxauth.service.common.*;
import org.gluu.oxauth.service.external.ExternalIntrospectionService;
import org.gluu.oxauth.service.external.context.ExternalIntrospectionContext;
import org.gluu.oxauth.util.TokenHashUtil;
import org.gluu.service.CacheService;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Base class for all the types of authorization grant.
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version April 10, 2020
 */
public class AuthorizationGrant extends AbstractAuthorizationGrant {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationGrant.class);

    @Inject
    private CacheService cacheService;

    @Inject
    private GrantService grantService;

    @Inject
    private IdTokenFactory idTokenFactory;

    @Inject
    private WebKeysConfiguration webKeysConfiguration;

    @Inject
    private ClientService clientService;

    @Inject
    private ExternalIntrospectionService externalIntrospectionService;

    @Inject
    private AttributeService attributeService;

    @Inject
    private SectorIdentifierService sectorIdentifierService;

    private boolean isCachedWithNoPersistence = false;

    public AuthorizationGrant() {
    }

    public AuthorizationGrant(User user, AuthorizationGrantType authorizationGrantType, Client client,
                              Date authenticationTime) {
        super(user, authorizationGrantType, client, authenticationTime);
    }

    public void init(User user, AuthorizationGrantType authorizationGrantType, Client client, Date authenticationTime) {
        super.init(user, authorizationGrantType, client, authenticationTime);
    }

    public IdToken createIdToken(
            IAuthorizationGrant grant, String nonce,
            AuthorizationCode authorizationCode, AccessToken accessToken, RefreshToken refreshToken,
            String state, Set<String> scopes, boolean includeIdTokenClaims, Function<JsonWebResponse, Void> preProcessing) throws Exception {
        JsonWebResponse jwr = idTokenFactory.createJwr(grant, nonce, authorizationCode, accessToken, refreshToken,
                state, scopes, includeIdTokenClaims, preProcessing);
        return new IdToken(jwr.toString(), jwr.getClaims().getClaimAsDate(JwtClaimName.ISSUED_AT),
                jwr.getClaims().getClaimAsDate(JwtClaimName.EXPIRATION_TIME));
    }

    @Override
    public String checkScopesPolicy(String scope) {
        final String result = super.checkScopesPolicy(scope);
        save();
        return result;
    }

    @Override
    public void save() {
        if (isCachedWithNoPersistence) {
            if (getAuthorizationGrantType() == AuthorizationGrantType.AUTHORIZATION_CODE) {
                saveInCache();
            } else if (getAuthorizationGrantType() == AuthorizationGrantType.CIBA) {
                saveCIBAInCache();
                saveInCache();
            } else {
                throw new UnsupportedOperationException(
                        "Grant caching is not supported for : " + getAuthorizationGrantType());
            }
        } else {
            if (BooleanUtils.isTrue(appConfiguration.getUseCacheForAllImplicitFlowObjects()) && isImplicitFlow()) {
                saveInCache();
                return;
            }
            saveImpl();
        }
    }

    private void saveInCache() {
        CacheGrant cachedGrant = new CacheGrant(this, appConfiguration);
        cacheService.put(cachedGrant.getExpiresIn(), cachedGrant.cacheKey(), cachedGrant);
    }

    private void saveCIBAInCache() {
        CIBACacheGrant cachedGrant = new CIBACacheGrant((CIBAGrant) this, appConfiguration);
        cacheService.put(cachedGrant.getExpiresIn(), cachedGrant.cacheKey(), cachedGrant);
    }

    public boolean isImplicitFlow() {
        return getAuthorizationGrantType() == null || getAuthorizationGrantType() == AuthorizationGrantType.IMPLICIT;
    }

    private void saveImpl() {
        String grantId = getGrantId();
        if (grantId != null && StringUtils.isNotBlank(grantId)) {
            final List<TokenLdap> grants = grantService.getGrantsByGrantId(grantId);
            if (grants != null && !grants.isEmpty()) {
                for (TokenLdap t : grants) {
                    initTokenFromGrant(t);
                    log.debug("Saving grant: " + grantId + ", code_challenge: " + getCodeChallenge());
                    grantService.mergeSilently(t);
                }
            }
        }
    }

    private void initTokenFromGrant(TokenLdap token) {
        final String nonce = getNonce();
        if (nonce != null) {
            token.setNonce(nonce);
        }
        token.setScope(getScopesAsString());
        token.setAuthMode(getAcrValues());
        token.setSessionDn(getSessionDn());
        token.setAuthenticationTime(getAuthenticationTime());
        token.setCodeChallenge(getCodeChallenge());
        token.setCodeChallengeMethod(getCodeChallengeMethod());
        token.setClaims(getClaims());

        final JwtAuthorizationRequest jwtRequest = getJwtAuthorizationRequest();
        if (jwtRequest != null && StringUtils.isNotBlank(jwtRequest.getEncodedJwt())) {
            token.setJwtRequest(jwtRequest.getEncodedJwt());
        }
    }

    @Override
    public AccessToken createAccessToken(String certAsPem, ExecutionContext context) {
        try {
            final AccessToken accessToken = super.createAccessToken(certAsPem, context);
            if (getClient().isAccessTokenAsJwt()) {
                accessToken.setCode(createAccessTokenAsJwt(accessToken, context));
            }
            if (accessToken.getExpiresIn() > 0) {
                persist(asToken(accessToken));
            }
            return accessToken;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private String createAccessTokenAsJwt(AccessToken accessToken, ExecutionContext context) throws Exception {
        final User user = getUser();
        final Client client = getClient();

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm
                .fromString(appConfiguration.getDefaultSignatureAlgorithm());
        if (client.getAccessTokenSigningAlg() != null
                && SignatureAlgorithm.fromString(client.getAccessTokenSigningAlg()) != null) {
            signatureAlgorithm = SignatureAlgorithm.fromString(client.getAccessTokenSigningAlg());
        }

        final JwtSigner jwtSigner = new JwtSigner(appConfiguration, webKeysConfiguration, signatureAlgorithm,
                client.getClientId(), clientService.decryptSecret(client.getClientSecret()));
        final Jwt jwt = jwtSigner.newJwt();
        jwt.getClaims().setClaim("scope", Lists.newArrayList(getScopes()));
        jwt.getClaims().setClaim("client_id", getClientId());
        jwt.getClaims().setClaim("username", user != null ? user.getAttribute("displayName") : null);
        jwt.getClaims().setClaim("token_type", accessToken.getTokenType().getName());
        jwt.getClaims().setExpirationTime(accessToken.getExpirationDate());
        jwt.getClaims().setIssuedAt(accessToken.getCreationDate());
        jwt.getClaims().setSubjectIdentifier(getSub());
        jwt.getClaims().setClaim("x5t#S256", accessToken.getX5ts256());
        Audience.setAudience(jwt.getClaims(), getClient());

        if (client.getAttributes().getRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims()) {
            runIntrospectionScriptAndInjectValuesIntoJwt(jwt, context);
        }

        return jwtSigner.sign().toString();
    }

    private void runIntrospectionScriptAndInjectValuesIntoJwt(Jwt jwt, ExecutionContext executionContext) {
        JSONObject responseAsJsonObject = new JSONObject();

        ExternalIntrospectionContext context = new ExternalIntrospectionContext(this, executionContext.getHttpRequest(), executionContext.getHttpResponse(), appConfiguration, attributeService);
        context.setAccessTokenAsJwt(jwt);
        if (externalIntrospectionService.executeExternalModifyResponse(responseAsJsonObject, context)) {
            log.trace("Successfully run external introspection scripts.");

            if (context.isTranferIntrospectionPropertiesIntoJwtClaims()) {
                log.trace("Transfering claims into jwt ...");
                JwtUtil.transferIntoJwtClaims(responseAsJsonObject, jwt);
                log.trace("Transfered.");
            }
        }
    }

    @Override
    public RefreshToken createRefreshToken() {
        try {
            final RefreshToken refreshToken = super.createRefreshToken();
            if (refreshToken.getExpiresIn() > 0) {
                persist(asToken(refreshToken));
            }
            return refreshToken;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public IdToken createIdToken(
            String nonce, AuthorizationCode authorizationCode, AccessToken accessToken, RefreshToken refreshToken,
            String state, AuthorizationGrant authorizationGrant, boolean includeIdTokenClaims, Function<JsonWebResponse, Void> preProcessing) {
        try {
            final IdToken idToken = createIdToken(this, nonce, authorizationCode, accessToken, refreshToken,
                    state, getScopes(), includeIdTokenClaims, preProcessing);
            final String acrValues = authorizationGrant.getAcrValues();
            final String sessionDn = authorizationGrant.getSessionDn();
            if (idToken.getExpiresIn() > 0) {
                final TokenLdap tokenLdap = asToken(idToken);
                tokenLdap.setAuthMode(acrValues);
                tokenLdap.setSessionDn(sessionDn);
                persist(tokenLdap);
            }

            setAcrValues(acrValues);
            setSessionDn(sessionDn);
            return idToken;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public void persist(TokenLdap p_token) {
        grantService.persist(p_token);
    }

    public void persist(AuthorizationCode p_code) {
        persist(asToken(p_code));
    }

    public TokenLdap asToken(IdToken p_token) {
        final TokenLdap result = asTokenLdap(p_token);
        result.setTokenTypeEnum(org.gluu.oxauth.model.ldap.TokenType.ID_TOKEN);
        return result;
    }

    public TokenLdap asToken(RefreshToken p_token) {
        final TokenLdap result = asTokenLdap(p_token);
        result.setTokenTypeEnum(org.gluu.oxauth.model.ldap.TokenType.REFRESH_TOKEN);
        return result;
    }

    public TokenLdap asToken(AuthorizationCode p_authorizationCode) {
        final TokenLdap result = asTokenLdap(p_authorizationCode);
        result.setTokenTypeEnum(org.gluu.oxauth.model.ldap.TokenType.AUTHORIZATION_CODE);
        return result;
    }

    public TokenLdap asToken(AccessToken p_accessToken) {
        final TokenLdap result = asTokenLdap(p_accessToken);
        result.setTokenTypeEnum(org.gluu.oxauth.model.ldap.TokenType.ACCESS_TOKEN);
        return result;
    }

    public String getScopesAsString() {
        final StringBuilder scopes = new StringBuilder();
        for (String s : getScopes()) {
            scopes.append(s).append(" ");
        }
        return scopes.toString().trim();
    }

    public TokenLdap asTokenLdap(AbstractToken p_token) {

        final TokenLdap result = new TokenLdap();
        final String hashedCode = TokenHashUtil.hash(p_token.getCode());

        result.setDn(grantService.buildDn(hashedCode));
        result.setGrantId(getGrantId());
        result.setCreationDate(p_token.getCreationDate());
        result.setExpirationDate(p_token.getExpirationDate());
        result.setTtl(p_token.getTtl());
        result.setTokenCode(hashedCode);
        result.setUserId(getUserId());
        result.setClientId(getClientId());

        result.getAttributes().setX5cs256(p_token.getX5ts256());

        final AuthorizationGrantType grantType = getAuthorizationGrantType();
        if (grantType != null) {
            result.setGrantType(grantType.getParamName());
        }

        final AuthorizationCode authorizationCode = getAuthorizationCode();
        if (authorizationCode != null) {
            result.setAuthorizationCode(TokenHashUtil.hash(authorizationCode.getCode()));
        }

        initTokenFromGrant(result);

        return result;
    }

    @Override
    public void revokeAllTokens() {
        final TokenLdap tokenLdap = getTokenLdap();
        if (tokenLdap != null && StringUtils.isNotBlank(tokenLdap.getGrantId())) {
            grantService.removeAllByGrantId(tokenLdap.getGrantId());
        }
    }

    @Override
    public void checkExpiredTokens() {
        // do nothing, clean up is made via grant service:
        // org.gluu.oxauth.service.GrantService.cleanUp()
    }

    public String getSub() {
        return sectorIdentifierService.getSub(this);
    }

    public boolean isCachedWithNoPersistence() {
        return isCachedWithNoPersistence;
    }

    public void setIsCachedWithNoPersistence(boolean isCachedWithNoPersistence) {
        this.isCachedWithNoPersistence = isCachedWithNoPersistence;
    }
}