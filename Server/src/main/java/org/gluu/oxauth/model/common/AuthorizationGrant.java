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
import org.gluu.model.metric.MetricType;
import org.gluu.oxauth.claims.Audience;
import org.gluu.oxauth.model.authorize.JwtAuthorizationRequest;
import org.gluu.oxauth.model.config.WebKeysConfiguration;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.jwt.JwtClaimName;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.token.HandleTokenFactory;
import org.gluu.oxauth.model.token.IdTokenFactory;
import org.gluu.oxauth.model.token.JsonWebResponse;
import org.gluu.oxauth.model.token.JwtSigner;
import org.gluu.oxauth.model.util.JwtUtil;
import org.gluu.oxauth.service.*;
import org.gluu.oxauth.service.external.ExternalIntrospectionService;
import org.gluu.oxauth.service.external.ExternalUpdateTokenService;
import org.gluu.oxauth.service.external.context.ExternalIntrospectionContext;
import org.gluu.oxauth.service.external.context.ExternalUpdateTokenContext;
import org.gluu.oxauth.service.stat.StatService;
import org.gluu.oxauth.util.TokenHashUtil;
import org.gluu.service.CacheService;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
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
public abstract class AuthorizationGrant extends AbstractAuthorizationGrant {

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

	@Inject
	private MetricService metricService;

	@Inject
    private StatService statService;

    @Inject
    private ExternalUpdateTokenService externalUpdateTokenService;

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
            String state, Set<String> scopes, boolean includeIdTokenClaims, Function<JsonWebResponse, Void> preProcessing,
            Function<JsonWebResponse, Void> postProcessing, ExecutionContext executionContext) throws Exception {
        JsonWebResponse jwr = idTokenFactory.createJwr(grant, nonce, authorizationCode, accessToken, refreshToken,
                state, scopes, includeIdTokenClaims, preProcessing, postProcessing, executionContext);
        final IdToken idToken = new IdToken(jwr.toString(), jwr.getClaims().getClaimAsDate(JwtClaimName.ISSUED_AT),
                jwr.getClaims().getClaimAsDate(JwtClaimName.EXPIRATION_TIME));
        if (log.isTraceEnabled())
            log.trace("Created id_token:" + idToken.getCode() );
        return idToken;
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
            context.setGrant(this);

            final AccessToken accessToken = super.createAccessToken(certAsPem, context);
            if (accessToken.getExpiresIn() < 0) {
                log.trace("Failed to create access token with negative expiration time");
                return null;
            }

            JwtSigner jwtSigner = null;
            if (getClient().isAccessTokenAsJwt()) {
                jwtSigner = createAccessTokenAsJwt(accessToken, context);
            }

            boolean externalOk = externalUpdateTokenService.modifyAccessToken(accessToken, ExternalUpdateTokenContext.of(context, jwtSigner));
            if (!externalOk) {
                log.trace("External script forbids access token creation.");
                return null;
            }

            if (getClient().isAccessTokenAsJwt() && jwtSigner != null) {
                final String accessTokenCode = jwtSigner.sign().toString();
                if (log.isTraceEnabled())
                    log.trace("Created access token JWT: {}", accessTokenCode + ", claims: " + jwtSigner.getJwt().getClaims().toJsonString());

                accessToken.setCode(accessTokenCode);
            }

            final TokenLdap tokenEntity = asToken(accessToken);
            context.setAccessTokenEntity(tokenEntity);

            persist(tokenEntity);

            statService.reportAccessToken(getGrantType());
            metricService.incCounter(MetricType.OXAUTH_TOKEN_ACCESS_TOKEN_COUNT);

            if (log.isTraceEnabled())
                log.trace("Created plain access token: {}", accessToken.getCode());

            return accessToken;
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private JwtSigner createAccessTokenAsJwt(AccessToken accessToken, ExecutionContext context) throws Exception {
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
        jwt.getClaims().setClaim("code", accessToken.getCode()); // guarantee uniqueness : without it we can get race condition
        jwt.getClaims().setExpirationTime(accessToken.getExpirationDate());
        jwt.getClaims().setIssuedAt(accessToken.getCreationDate());
        jwt.getClaims().setSubjectIdentifier(getSub());
        jwt.getClaims().setClaim("x5t#S256", accessToken.getX5ts256());
        Audience.setAudience(jwt.getClaims(), getClient());

        if (client.getAttributes().getRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims()) {
            runIntrospectionScriptAndInjectValuesIntoJwt(jwt, context);
        }

        return jwtSigner;
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
    public RefreshToken createRefreshToken(ExecutionContext executionContext) {
        try {
            final int refreshTokenLifetimeInSeconds = externalUpdateTokenService.getRefreshTokenLifetimeInSeconds(ExternalUpdateTokenContext.of(executionContext));
            executionContext.setRefreshTokenLifetimeFromScript(refreshTokenLifetimeInSeconds);

            final RefreshToken refreshToken = super.createRefreshToken(executionContext);
            if (refreshToken.getExpiresIn() > 0) {
                final TokenLdap entity = asToken(refreshToken);
                executionContext.setRefreshTokenEntity(entity);

                boolean externalOk = externalUpdateTokenService.modifyRefreshToken(refreshToken, ExternalUpdateTokenContext.of(executionContext));
                if (!externalOk) {
                    log.trace("External script forbids refresh token creation.");
                    return null;
                }

                persist(entity);
            }

            statService.reportRefreshToken(getGrantType());
            metricService.incCounter(MetricType.OXAUTH_TOKEN_REFRESH_TOKEN_COUNT);

            if (log.isTraceEnabled())
                log.trace("Created refresh token: " + refreshToken.getCode());

            return refreshToken;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public RefreshToken createRefreshToken(ExecutionContext executionContext, Date expirationDate) {
        try {
            RefreshToken refreshToken = new RefreshToken(HandleTokenFactory.generateHandleToken(), new Date(), expirationDate);

            refreshToken.setAuthMode(getAcrValues());
            refreshToken.setSessionDn(getSessionDn());

            if (refreshToken.getExpiresIn() > 0) {
                final TokenLdap entity = asToken(refreshToken);
                executionContext.setRefreshTokenEntity(entity);

                boolean externalOk = externalUpdateTokenService.modifyRefreshToken(refreshToken, ExternalUpdateTokenContext.of(executionContext));
                if (!externalOk) {
                    log.trace("External script forbids refresh token creation.");
                    return null;
                }

                persist(entity);
                statService.reportRefreshToken(getGrantType());
                metricService.incCounter(MetricType.OXAUTH_TOKEN_REFRESH_TOKEN_COUNT);

                if (log.isTraceEnabled())
                    log.trace("Created refresh token: " + refreshToken.getCode());

                return refreshToken;
            }

            log.debug("Token expiration date is in the past. Skip creation.");
            return null;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public IdToken createIdToken(
            String nonce, AuthorizationCode authorizationCode, AccessToken accessToken, RefreshToken refreshToken,
            String state, AuthorizationGrant authorizationGrant, boolean includeIdTokenClaims, Function<JsonWebResponse, Void> preProcessing,
            Function<JsonWebResponse, Void> postProcessing, ExecutionContext executionContext) {
        try {
            final IdToken idToken = createIdToken(this, nonce, authorizationCode, accessToken, refreshToken,
                    state, getScopes(), includeIdTokenClaims, preProcessing, postProcessing, executionContext);
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

            statService.reportIdToken(getGrantType());
            metricService.incCounter(MetricType.OXAUTH_TOKEN_ID_TOKEN_COUNT);

            return idToken;
        } catch (WebApplicationException e) {
            throw e;
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