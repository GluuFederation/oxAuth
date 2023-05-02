/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import com.google.common.base.Function;
import org.gluu.oxauth.model.authorize.JwtAuthorizationRequest;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.token.JsonWebResponse;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version September 4, 2019
 */

public interface IAuthorizationGrant {

    GrantType getGrantType();

    String getGrantId();

    void setGrantId(String p_grantId);

    AuthorizationCode getAuthorizationCode();

    void setAuthorizationCode(AuthorizationCode authorizationCode);

    String getNonce();

    void setNonce(String nonce);

    String getSub();

    AccessToken createAccessToken(String certAsPem, ExecutionContext executionContext);

    RefreshToken createRefreshToken(ExecutionContext executionContext);

    IdToken createIdToken(
            String nonce, AuthorizationCode authorizationCode, AccessToken accessToken, RefreshToken refreshToken,
            String state, AuthorizationGrant authorizationGrant, boolean includeIdTokenClaims,
            Function<JsonWebResponse, Void> preProcessing, Function<JsonWebResponse, Void> postProcessing,
            ExecutionContext executionContext);

    RefreshToken getRefreshToken(String refreshTokenCode);

    AbstractToken getAccessToken(String tokenCode);

    void revokeAllTokens();

    void checkExpiredTokens();

    String checkScopesPolicy(String scope);

    User getUser();

    String getUserId();

    String getUserDn();

    AuthorizationGrantType getAuthorizationGrantType();

    String getClientId();

    Client getClient();

    String getClientDn();

    List<AccessToken> getAccessTokens();

    Set<String> getScopes();

    Set<String> getRefreshTokensCodes();

    Set<String> getAccessTokensCodes();

    List<RefreshToken> getRefreshTokens();

    void setRefreshTokens(List<RefreshToken> refreshTokens);

    AccessToken getLongLivedAccessToken();

    IdToken getIdToken();

    JwtAuthorizationRequest getJwtAuthorizationRequest();

    void setJwtAuthorizationRequest(JwtAuthorizationRequest p_jwtAuthorizationRequest);

    Date getAuthenticationTime();

    TokenLdap getTokenLdap();

    void setTokenLdap(TokenLdap p_tokenLdap);

    void setLongLivedAccessToken(AccessToken longLivedAccessToken);

    void setIdToken(IdToken idToken);

    void setScopes(Collection<String> scopes);

    void setAccessTokens(List<AccessToken> accessTokens);

    String getAcrValues();

    void setAcrValues(String authMode);

    String getSessionDn();

    void setSessionDn(String sessionDn);

    /**
     * Saves changes asynchronously
     */
    void save();
}