/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import org.apache.commons.lang.StringUtils;
import org.gluu.model.metric.MetricType;
import org.gluu.oxauth.model.authorize.JwtAuthorizationRequest;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.ldap.TokenType;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.GrantService;
import org.gluu.oxauth.service.MetricService;
import org.gluu.oxauth.service.common.UserService;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.oxauth.util.TokenHashUtil;
import org.gluu.service.CacheService;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Component to hold in memory authorization grant objects.
 *
 * @author Javier Rojas Blum
 * @version February 25, 2020
 */
@Dependent
public class AuthorizationGrantList implements IAuthorizationGrantList {

    @Inject
    private Logger log;

    @Inject
    private Instance<AbstractAuthorizationGrant> grantInstance;

    @Inject
    private GrantService grantService;

    @Inject
    private UserService userService;

    @Inject
    private ClientService clientService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private CacheService cacheService;

    @Inject
    private AbstractCryptoProvider cryptoProvider;

	@Inject
	private MetricService metricService;

    @Override
    public void removeAuthorizationGrants(List<AuthorizationGrant> authorizationGrants) {
        if (authorizationGrants != null && !authorizationGrants.isEmpty()) {
            for (AuthorizationGrant r : authorizationGrants) {
                grantService.remove(r);
            }
        }
    }

    @Override
    public AuthorizationGrant createAuthorizationGrant(User user, Client client, Date authenticationTime) {
        AuthorizationGrant grant = grantInstance.select(SimpleAuthorizationGrant.class).get();
        grant.init(user, null, client, authenticationTime);

        return grant;
    }

    @Override
    public AuthorizationCodeGrant createAuthorizationCodeGrant(User user, Client client, Date authenticationTime) {
        AuthorizationCodeGrant grant = grantInstance.select(AuthorizationCodeGrant.class).get();
        grant.init(user, client, authenticationTime);

        CacheGrant memcachedGrant = new CacheGrant(grant, appConfiguration);
        cacheService.put(grant.getAuthorizationCode().getExpiresIn(), memcachedGrant.cacheKey(), memcachedGrant);
        log.trace("Put authorization grant in cache, code: " + grant.getAuthorizationCode().getCode() + ", clientId: " + grant.getClientId());
        
        metricService.incCounter(MetricType.OXAUTH_TOKEN_AUTHORIZATION_CODE_COUNT);
        return grant;
    }

    @Override
    public ImplicitGrant createImplicitGrant(User user, Client client, Date authenticationTime) {
        ImplicitGrant grant = grantInstance.select(ImplicitGrant.class).get();
        grant.init(user, client, authenticationTime);

        return grant;
    }

    @Override
    public ClientCredentialsGrant createClientCredentialsGrant(User user, Client client) {
        ClientCredentialsGrant grant = grantInstance.select(ClientCredentialsGrant.class).get();
        grant.init(user, client);

        return grant;
    }

    @Override
    public ResourceOwnerPasswordCredentialsGrant createResourceOwnerPasswordCredentialsGrant(User user, Client client) {
        ResourceOwnerPasswordCredentialsGrant grant = grantInstance.select(ResourceOwnerPasswordCredentialsGrant.class).get();
        grant.init(user, client);

        return grant;
    }

    @Override
    public CIBAGrant createCIBAGrant(CibaRequestCacheControl request) {
        CIBAGrant grant = grantInstance.select(CIBAGrant.class).get();
        grant.init(request);

        CacheGrant memcachedGrant = new CacheGrant(grant, appConfiguration);
        cacheService.put(request.getExpiresIn(), memcachedGrant.getAuthReqId(), memcachedGrant);
        log.trace("Ciba grant saved in cache, authReqId: {}, grantId: {}", grant.getAuthReqId(), grant.getGrantId());
        return grant;
    }

    @Override
    public CIBAGrant getCIBAGrant(String authReqId) {
        Object cachedGrant = cacheService.get(authReqId);
        if (cachedGrant == null) {
            // retry one time : sometimes during high load cache client may be not fast enough
            cachedGrant = cacheService.get(authReqId);
            log.trace("Failed to fetch CIBA grant from cache, authReqId: {}", authReqId);
        }
        return cachedGrant instanceof CacheGrant ? ((CacheGrant) cachedGrant).asCibaGrant(grantInstance) : null;
    }

    @Override
    public DeviceCodeGrant createDeviceGrant(DeviceAuthorizationCacheControl data, User user) {
        DeviceCodeGrant grant = grantInstance.select(DeviceCodeGrant.class).get();
        grant.init(data, user);

        CacheGrant memcachedGrant = new CacheGrant(grant, appConfiguration);
        cacheService.put(data.getExpiresIn(), memcachedGrant.getDeviceCode(), memcachedGrant);
        log.trace("Device code grant saved in cache, deviceCode: {}, grantId: {}", grant.getDeviceCode(), grant.getGrantId());
        return grant;
    }

    @Override
    public DeviceCodeGrant getDeviceCodeGrant(String deviceCode) {
        Object cachedGrant = cacheService.get(deviceCode);
        if (cachedGrant == null) {
            // retry one time : sometimes during high load cache client may be not fast enough
            cachedGrant = cacheService.get(deviceCode);
            log.trace("Failed to fetch Device code grant from cache, deviceCode: {}", deviceCode);
        }
        return cachedGrant instanceof CacheGrant ? ((CacheGrant) cachedGrant).asDeviceCodeGrant(grantInstance) : null;
    }

    @Override
    public AuthorizationCodeGrant getAuthorizationCodeGrant(String authorizationCode) {
        Object cachedGrant = cacheService.get(CacheGrant.cacheKey(authorizationCode, null));
        if (cachedGrant == null) {
            // retry one time : sometimes during high load cache client may be not fast enough
            cachedGrant = cacheService.get(CacheGrant.cacheKey(authorizationCode, null));
            log.trace("Failed to fetch authorization grant from cache, code: " + authorizationCode);
        }
        return cachedGrant instanceof CacheGrant ? ((CacheGrant) cachedGrant).asCodeGrant(grantInstance) : null;
    }

    @Override
    public AuthorizationGrant getAuthorizationGrantByRefreshToken(String clientId, String refreshTokenCode) {
        if (!ServerUtil.isTrue(appConfiguration.getPersistRefreshTokenInLdap())) {
            return assertTokenType((TokenLdap) cacheService.get(TokenHashUtil.hash(refreshTokenCode)), TokenType.REFRESH_TOKEN, clientId);
        }
        return assertTokenType(grantService.getGrantByCode(refreshTokenCode), TokenType.REFRESH_TOKEN, clientId);
    }

    public AuthorizationGrant assertTokenType(TokenLdap tokenLdap, TokenType tokenType, String clientId) {
        if (tokenLdap == null || tokenLdap.getTokenTypeEnum() != tokenType) {
            return null;
        }

        final AuthorizationGrant grant = asGrant(tokenLdap);
        if (grant == null || !grant.getClientId().equals(clientId)) {
            return null;
        }
        return grant;
    }

    @Override
    public List<AuthorizationGrant> getAuthorizationGrant(String clientId) {
        final List<AuthorizationGrant> result = new ArrayList<>();
        try {
            final List<TokenLdap> entries = new ArrayList<TokenLdap>();
            entries.addAll(grantService.getGrantsOfClient(clientId));
            entries.addAll(grantService.getCacheClientTokensEntries(clientId));

            for (TokenLdap t : entries) {
                final AuthorizationGrant grant = asGrant(t);
                if (grant != null) {
                    result.add(grant);
                }
            }
        } catch (Exception e) {
            log.trace(e.getMessage(), e);
        }
        return result;
    }

    @Override
    public AuthorizationGrant getAuthorizationGrantByAccessToken(String accessToken) {
        return getAuthorizationGrantByAccessToken(accessToken, false);
    }

    public AuthorizationGrant getAuthorizationGrantByAccessToken(String accessToken, boolean onlyFromCache) {
        final TokenLdap tokenLdap = grantService.getGrantByCode(accessToken);
        if (tokenLdap != null    && (tokenLdap.getTokenTypeEnum() == org.gluu.oxauth.model.ldap.TokenType.ACCESS_TOKEN || tokenLdap.getTokenTypeEnum() == org.gluu.oxauth.model.ldap.TokenType.LONG_LIVED_ACCESS_TOKEN)) {
            return asGrant(tokenLdap);
        }
        return null;
    }

    @Override
    public AuthorizationGrant getAuthorizationGrantByIdToken(String idToken) {
        if (StringUtils.isBlank(idToken)) {
            return null;
        }
        final TokenLdap tokenLdap = grantService.getGrantByCode(idToken);
        if (tokenLdap != null && (tokenLdap.getTokenTypeEnum() == org.gluu.oxauth.model.ldap.TokenType.ID_TOKEN)) {
            return asGrant(tokenLdap);
        }
        return null;
    }

    public AuthorizationGrant asGrant(TokenLdap tokenLdap) {
        if (tokenLdap != null) {
            final AuthorizationGrantType grantType = AuthorizationGrantType.fromString(tokenLdap.getGrantType());
            if (grantType != null) {
            	String userId = tokenLdap.getUserId();
            	User user = null;
            	if (StringHelper.isNotEmpty(userId)) {
                    user = userService.getUser(userId);
            	}
                final Client client = clientService.getClient(tokenLdap.getClientId());
                final Date authenticationTime = tokenLdap.getAuthenticationTime();
                final String nonce = tokenLdap.getNonce();

                AuthorizationGrant result;
                switch (grantType) {
                    case AUTHORIZATION_CODE:
                        AuthorizationCodeGrant authorizationCodeGrant = grantInstance.select(AuthorizationCodeGrant.class).get();
                        authorizationCodeGrant.init(user, client, authenticationTime);

                        result = authorizationCodeGrant;
                        break;
                    case CLIENT_CREDENTIALS:
                        ClientCredentialsGrant clientCredentialsGrant = grantInstance.select(ClientCredentialsGrant.class).get();
                        clientCredentialsGrant.init(user, client);

                        result = clientCredentialsGrant;
                        break;
                    case IMPLICIT:
                        ImplicitGrant implicitGrant = grantInstance.select(ImplicitGrant.class).get();
                        implicitGrant.init(user, client, authenticationTime);

                        result = implicitGrant;
                        break;
                    case RESOURCE_OWNER_PASSWORD_CREDENTIALS:
                        ResourceOwnerPasswordCredentialsGrant resourceOwnerPasswordCredentialsGrant = grantInstance.select(ResourceOwnerPasswordCredentialsGrant.class).get();
                        resourceOwnerPasswordCredentialsGrant.init(user, client);

                        result = resourceOwnerPasswordCredentialsGrant;
                        break;
                    case CIBA:
                        CIBAGrant cibaGrant = grantInstance.select(CIBAGrant.class).get();
                        cibaGrant.init(user, AuthorizationGrantType.CIBA, client, tokenLdap.getCreationDate());

                        result = cibaGrant;
                        break;
                    case DEVICE_CODE:
                        DeviceCodeGrant deviceCodeGrant = grantInstance.select(DeviceCodeGrant.class).get();
                        deviceCodeGrant.init(user, AuthorizationGrantType.DEVICE_CODE, client, tokenLdap.getCreationDate());

                        result = deviceCodeGrant;
                        break;
                    default:
                        return null;
                }

                final String grantId = tokenLdap.getGrantId();
                final String jwtRequest = tokenLdap.getJwtRequest();
                final String authMode = tokenLdap.getAuthMode();
                final String sessionDn = tokenLdap.getSessionDn();
                final String claims = tokenLdap.getClaims();

                result.setTokenBindingHash(tokenLdap.getTokenBindingHash());
                result.setNonce(nonce);
                result.setX5ts256(tokenLdap.getAttributes().getX5cs256());
                result.setTokenLdap(tokenLdap);
                if (StringUtils.isNotBlank(grantId)) {
                    result.setGrantId(grantId);
                }
                result.setScopes(Util.splittedStringAsList(tokenLdap.getScope(), " "));

                result.setCodeChallenge(tokenLdap.getCodeChallenge());
                result.setCodeChallengeMethod(tokenLdap.getCodeChallengeMethod());

                if (StringUtils.isNotBlank(jwtRequest)) {
                    try {
                        result.setJwtAuthorizationRequest(new JwtAuthorizationRequest(appConfiguration, cryptoProvider, jwtRequest, client));
                    } catch (Exception e) {
                        log.trace(e.getMessage(), e);
                    }
                }

                result.setAcrValues(authMode);
                result.setSessionDn(sessionDn);
                result.setClaims(claims);

                if (tokenLdap.getTokenTypeEnum() != null) {
                    switch (tokenLdap.getTokenTypeEnum()) {
                        case AUTHORIZATION_CODE:
                            if (result instanceof AuthorizationCodeGrant) {
                                final AuthorizationCode code = new AuthorizationCode(tokenLdap.getTokenCode(), tokenLdap.getCreationDate(), tokenLdap.getExpirationDate());
                                final AuthorizationCodeGrant g = (AuthorizationCodeGrant) result;
                                code.setX5ts256(g.getX5ts256());
                                g.setAuthorizationCode(code);
                            }
                            break;
                        case REFRESH_TOKEN:
                            final RefreshToken refreshToken = new RefreshToken(tokenLdap.getTokenCode(), tokenLdap.getCreationDate(), tokenLdap.getExpirationDate());
                            refreshToken.setX5ts256(result.getX5ts256());
                            result.setRefreshTokens(Arrays.asList(refreshToken));
                            break;
                        case ACCESS_TOKEN:
                            final AccessToken accessToken = new AccessToken(tokenLdap.getTokenCode(), tokenLdap.getCreationDate(), tokenLdap.getExpirationDate());
                            accessToken.setX5ts256(result.getX5ts256());
                            result.setAccessTokens(Arrays.asList(accessToken));
                            break;
                        case ID_TOKEN:
                            final IdToken idToken = new IdToken(tokenLdap.getTokenCode(), tokenLdap.getCreationDate(), tokenLdap.getExpirationDate());
                            idToken.setX5ts256(result.getX5ts256());
                            result.setIdToken(idToken);
                            break;
                        case LONG_LIVED_ACCESS_TOKEN:
                            final AccessToken longLivedAccessToken = new AccessToken(tokenLdap.getTokenCode(), tokenLdap.getCreationDate(), tokenLdap.getExpirationDate());
                            longLivedAccessToken.setX5ts256(result.getX5ts256());
                            result.setLongLivedAccessToken(longLivedAccessToken);
                            break;
                    }
                }
                return result;
            }
        }
        return null;
    }

}
