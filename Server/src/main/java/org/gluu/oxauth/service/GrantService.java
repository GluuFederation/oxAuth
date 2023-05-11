/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service;

import com.google.common.collect.Lists;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.common.AuthorizationGrant;
import org.gluu.oxauth.model.common.CacheGrant;
import org.gluu.oxauth.model.common.ClientTokens;
import org.gluu.oxauth.model.common.SessionTokens;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.ldap.TokenType;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.util.TokenHashUtil;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.search.filter.Filter;
import org.gluu.service.CacheService;
import org.gluu.service.cache.CacheConfiguration;
import org.gluu.service.cache.CacheProviderType;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.*;

import static org.gluu.oxauth.util.ServerUtil.isTrue;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version November 28, 2018
 */
@ApplicationScoped
public class GrantService {

    @Inject
    private Logger log;

    @Inject
    private PersistenceEntryManager ldapEntryManager;

    @Inject
    private ClientService clientService;

    @Inject
    private CacheService cacheService;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private CacheConfiguration cacheConfiguration;

    public static String generateGrantId() {
        return UUID.randomUUID().toString();
    }

    public String buildDn(String p_hashedToken) {
        return String.format("tknCde=%s,", p_hashedToken) + tokenBaseDn();
    }

    private String tokenBaseDn() {
        return staticConfiguration.getBaseDn().getTokens();  // ou=tokens,o=gluu
    }

    public void merge(TokenLdap p_token) {
        ldapEntryManager.merge(p_token);
    }

    public void mergeSilently(TokenLdap p_token) {
        try {
            ldapEntryManager.merge(p_token);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private boolean shouldPutInCache(TokenType tokenType, boolean isImplicitFlow) {
        if (cacheConfiguration.getCacheProviderType() == CacheProviderType.NATIVE_PERSISTENCE) {
            return false;
        }

        if (isImplicitFlow && BooleanUtils.isTrue(appConfiguration.getUseCacheForAllImplicitFlowObjects())) {
            return true;
        }

        switch (tokenType) {
            case ID_TOKEN:
                if (!isTrue(appConfiguration.getPersistIdTokenInLdap())) {
                    return true;
                }
            case REFRESH_TOKEN:
                if (!isTrue(appConfiguration.getPersistRefreshTokenInLdap())) {
                    return true;
                }
        }
        return false;
    }

    public void persist(TokenLdap token) {
        if (shouldPutInCache(token.getTokenTypeEnum(), token.isImplicitFlow())) {
            ClientTokens clientTokens = getCacheClientTokens(token.getClientId());
            clientTokens.getTokenHashes().add(token.getTokenCode());

            int expiration = appConfiguration.getDynamicRegistrationExpirationTime(); // fallback to client's lifetime
            switch (token.getTokenTypeEnum()) {
                case ID_TOKEN:
                    expiration = appConfiguration.getIdTokenLifetime();
                    break;
                case REFRESH_TOKEN:
                    expiration = appConfiguration.getRefreshTokenLifetime();
                    break;
                case ACCESS_TOKEN:
                case LONG_LIVED_ACCESS_TOKEN:
                    int lifetime = appConfiguration.getAccessTokenLifetime();
                    Client client = clientService.getClient(token.getClientId());
                    // oxAuth #830 Client-specific access token expiration
                    if (client != null && client.getAccessTokenLifetime() != null && client.getAccessTokenLifetime() > 0) {
                        lifetime = client.getAccessTokenLifetime();
                    }
                    expiration = lifetime;
                    break;
                case AUTHORIZATION_CODE:
                    expiration = appConfiguration.getAuthorizationCodeLifetime();
                    break;
            }

            token.setIsFromCache(true);
            cacheService.put(expiration, token.getTokenCode(), token);
            cacheService.put(expiration, clientTokens.cacheKey(), clientTokens);

            if (StringUtils.isNotBlank(token.getSessionDn())) {
                SessionTokens sessionTokens = getCacheSessionTokens(token.getSessionDn());
                sessionTokens.getTokenHashes().add(token.getTokenCode());

                cacheService.put(expiration, sessionTokens.cacheKey(), sessionTokens);
            }
            return;
        }

        ldapEntryManager.persist(token);
    }

    public ClientTokens getCacheClientTokens(String clientId) {
        ClientTokens clientTokens = new ClientTokens(clientId);
        Object o = cacheService.get(clientTokens.cacheKey());
        if (o instanceof ClientTokens) {
            return (ClientTokens) o;
        } else {
            return clientTokens;
        }
    }

    public SessionTokens getCacheSessionTokens(String sessionDn) {
        SessionTokens sessionTokens = new SessionTokens(sessionDn);
        Object o = cacheService.get(sessionTokens.cacheKey());
        if (o instanceof SessionTokens) {
            return (SessionTokens) o;
        } else {
            return sessionTokens;
        }
    }

    public void remove(TokenLdap p_token) {
        if (p_token.isFromCache()) {
            cacheService.remove(p_token.getTokenCode());
            log.trace("Removed token from cache, code: " + p_token.getTokenCode());
        } else {
            ldapEntryManager.remove(p_token);
            log.trace("Removed token from LDAP, code: " + p_token.getTokenCode());
        }
    }

    public void removeSilently(TokenLdap token) {
        try {
            remove(token);

            if (StringUtils.isNotBlank(token.getAuthorizationCode())) {
                cacheService.remove(CacheGrant.cacheKey(token.getAuthorizationCode(), token.getGrantId()));
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void remove(List<TokenLdap> p_entries) {
        if (p_entries != null && !p_entries.isEmpty()) {
            for (TokenLdap t : p_entries) {
                try {
                    remove(t);
                } catch (Exception e) {
                    log.error("Failed to remove entry", e);
                }
            }
        }
    }

    public void removeSilently(List<TokenLdap> p_entries) {
        if (p_entries != null && !p_entries.isEmpty()) {
            for (TokenLdap t : p_entries) {
                removeSilently(t);
            }
        }
    }

    public void remove(AuthorizationGrant p_grant) {
        if (p_grant != null && p_grant.getTokenLdap() != null) {
            try {
                remove(p_grant.getTokenLdap());
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
    }

    public List<TokenLdap> getGrantsOfClient(String p_clientId) {
        try {
            final String baseDn = clientService.buildClientDn(p_clientId);
            return ldapEntryManager.findEntries(baseDn, TokenLdap.class, Filter.createPresenceFilter("tknCde"));
        } catch (Exception e) {
            logException(e);
        }
        return Collections.emptyList();
    }

    public TokenLdap getGrantByCode(String p_code) {
        Object grant = cacheService.get(TokenHashUtil.hash(p_code));
        if (grant instanceof TokenLdap) {
            return (TokenLdap) grant;
        } else {
            return load(buildDn(TokenHashUtil.hash(p_code)));
        }
    }

    private TokenLdap load(String p_tokenDn) {
        try {
            final TokenLdap entry = ldapEntryManager.find(TokenLdap.class, p_tokenDn);
            return entry;
        } catch (Exception e) {
            logException(e);
        }
        return null;
    }

    public List<TokenLdap> getGrantsByGrantId(String p_grantId) {
        try {
            return ldapEntryManager.findEntries(tokenBaseDn(), TokenLdap.class, Filter.createEqualityFilter("grtId", p_grantId));
        } catch (Exception e) {
            logException(e);
        }
        return Collections.emptyList();
    }

    public List<TokenLdap> getGrantsByAuthorizationCode(String p_authorizationCode) {
        try {
            return ldapEntryManager.findEntries(tokenBaseDn(), TokenLdap.class, Filter.createEqualityFilter("authzCode", TokenHashUtil.hash(p_authorizationCode)));
        } catch (Exception e) {
            logException(e);
        }
        return Collections.emptyList();
    }

    public List<TokenLdap> getGrantsBySessionDn(String sessionDn) {
        List<TokenLdap> grants = new ArrayList<>();
        try {
            List<TokenLdap> ldapGrants = ldapEntryManager.findEntries(tokenBaseDn(), TokenLdap.class, Filter.createEqualityFilter("ssnId", sessionDn));
            if (ldapGrants != null) {
                grants.addAll(ldapGrants);
            }
            grants.addAll(getGrantsFromCacheBySessionDn(sessionDn));
        } catch (Exception e) {
            logException(e);
        }
        return grants;
    }

    private void logException(Exception e) {
        if (BooleanUtils.isTrue(appConfiguration.getLogNotFoundEntityAsError())) {
            log.error(e.getMessage(), e);
        } else {
            log.trace(e.getMessage(), e);
        }
    }

    public List<TokenLdap> getGrantsFromCacheBySessionDn(String sessionDn) {
        if (StringUtils.isBlank(sessionDn)) {
            return Collections.emptyList();
        }
        return getCacheTokensEntries(getCacheSessionTokens(sessionDn).getTokenHashes());
    }

    public List<TokenLdap> getCacheClientTokensEntries(String clientId) {
        if (cacheConfiguration.getCacheProviderType() == CacheProviderType.NATIVE_PERSISTENCE) {
            return Collections.emptyList();
        }
        Object o = cacheService.get(new ClientTokens(clientId).cacheKey());
        if (o instanceof ClientTokens) {
            return getCacheTokensEntries(((ClientTokens) o).getTokenHashes());
        }
        return Collections.emptyList();
    }

    public List<TokenLdap> getCacheTokensEntries(Set<String> tokenHashes) {
        List<TokenLdap> tokens = new ArrayList<>();

        for (String tokenHash : tokenHashes) {
            Object o1 = cacheService.get(tokenHash);
            if (o1 instanceof TokenLdap) {
                TokenLdap token = (TokenLdap) o1;
                token.setIsFromCache(true);
                tokens.add(token);
            }
        }
        return tokens;
    }

    public void logout(String sessionDn) {
        final List<TokenLdap> tokens = getGrantsBySessionDn(sessionDn);
        if (!appConfiguration.getRemoveRefreshTokensForClientOnLogout()) {
            List<TokenLdap> refreshTokens = Lists.newArrayList();
            for (TokenLdap token : tokens) {
                if (token.getTokenTypeEnum() == TokenType.REFRESH_TOKEN) {
                    refreshTokens.add(token);
                }
            }
            if (!refreshTokens.isEmpty()) {
                log.trace("Refresh tokens are not removed on logout (because removeRefreshTokensForClientOnLogout configuration property is false)");
                tokens.removeAll(refreshTokens);
            }
        }
        removeSilently(tokens);
    }

    public void removeAllTokensBySession(String sessionDn, boolean logout) {
        removeSilently(getGrantsBySessionDn(sessionDn));
    }

    /**
     * Removes grant with particular code.
     *
     * @param p_code code
     */
    public void removeByCode(String p_code) {
        final TokenLdap t = getGrantByCode(p_code);
        if (t != null) {
            removeSilently(t);
        }
        cacheService.remove(CacheGrant.cacheKey(p_code, null));
    }

    // authorization code is saved only in cache
    public void removeAuthorizationCode(String code) {
        cacheService.remove(CacheGrant.cacheKey(code, null));
    }

    public void removeAllByAuthorizationCode(String p_authorizationCode) {
        removeSilently(getGrantsByAuthorizationCode(p_authorizationCode));
    }

    public void removeAllByGrantId(String p_grantId) {
        removeSilently(getGrantsByGrantId(p_grantId));
    }

}