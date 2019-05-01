/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.ldap;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.common.GrantType;
import org.gluu.persist.annotation.*;

import java.io.Serializable;
import java.util.Date;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version September 6, 2017
 */

@DataEntry
@ObjectClass(values = {"top", "oxAuthToken"})
public class TokenLdap implements Serializable {

    @DN
    private String dn;
    @AttributeName(name = "uniqueIdentifier")
    private String id;
    @AttributeName(name = "oxAuthGrantId")
    private String grantId;
    @AttributeName(name = "oxAuthUserId")
    private String userId;
    @AttributeName(name = "oxAuthClientId")
    private String clientId;
    @AttributeName(name = "oxAuthCreation")
    private Date creationDate;
    @AttributeName(name = "oxAuthExpiration")
    private Date expirationDate;
    @AttributeName(name = "oxDeletable")
    private boolean deletable = true;
    @AttributeName(name = "oxAuthAuthenticationTime")
    private Date authenticationTime;
    @AttributeName(name = "oxAuthScope")
    private String scope;
    @AttributeName(name = "oxAuthTokenCode")
    private String tokenCode;
    @AttributeName(name = "oxAuthTokenType")
    private String tokenType;
    @AttributeName(name = "oxAuthGrantType")
    private String grantType;
    @AttributeName(name = "oxAuthJwtRequest")
    private String jwtRequest;
    @AttributeName(name = "oxAuthAuthorizationCode")
    private String authorizationCode;
    @AttributeName(name = "oxAuthNonce")
    private String nonce;
    @AttributeName(name = "oxCodeChallenge")
    private String codeChallenge;
    @AttributeName(name = "oxCodeChallengeMethod")
    private String codeChallengeMethod;
    @AttributeName(name = "oxAuthClaims")
    private String claims;
    @AttributeName(name = "oxIdTokenTokenBindingCnf")
    private String tokenBindingHash;

    @AttributeName(name = "oxAuthenticationMode")
    private String authMode;

    @AttributeName(name = "oxAuthSessionDn")
    private String sessionDn;

    @AttributeName(name = "oxAttributes")
    @JsonObject
    private TokenAttributes attributes;

    private boolean isFromCache;

    public TokenLdap() {
    }

    public TokenAttributes getAttributes() {
        if (attributes == null) {
            attributes = new TokenAttributes();
        }
        return attributes;
    }

    public final void setAttributes(TokenAttributes attributes) {
        this.attributes = attributes;
    }

    public boolean isDeletable() {
        return deletable;
    }

    public void setDeletable(boolean deletable) {
        this.deletable = deletable;
    }

    public String getId() {
        return id;
    }

    public void setId(String p_id) {
        id = p_id;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(String p_authorizationCode) {
        authorizationCode = p_authorizationCode;
    }

    public String getTokenBindingHash() {
        return tokenBindingHash;
    }

    public void setTokenBindingHash(String tokenBindingHash) {
        this.tokenBindingHash = tokenBindingHash;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getGrantId() {
        return grantId;
    }

    public void setGrantId(String p_grantId) {
        grantId = p_grantId;
    }

    public Date getAuthenticationTime() {
        return authenticationTime;
    }

    public void setAuthenticationTime(Date p_authenticationTime) {
        authenticationTime = p_authenticationTime;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(Date p_creationDate) {
        creationDate = p_creationDate;
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String p_dn) {
        dn = p_dn;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date p_expirationDate) {
        expirationDate = p_expirationDate;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String p_grantType) {
        grantType = p_grantType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String p_scope) {
        scope = p_scope;
    }

    public String getTokenCode() {
        return tokenCode;
    }

    public void setTokenCode(String p_tokenCode) {
        tokenCode = p_tokenCode;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String p_tokenType) {
        tokenType = p_tokenType;
    }

    public TokenType getTokenTypeEnum() {
        return TokenType.fromValue(tokenType);
    }

    public void setTokenTypeEnum(TokenType p_tokenType) {
        if (p_tokenType != null) {
            tokenType = p_tokenType.getValue();
        }
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String p_userId) {
        userId = p_userId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getJwtRequest() {
        return jwtRequest;
    }

    public void setJwtRequest(String p_jwtRequest) {
        jwtRequest = p_jwtRequest;
    }

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public String getClaims() {
        return claims;
    }

    public void setClaims(String claims) {
        this.claims = claims;
    }

    public String getSessionDn() {
        return sessionDn;
    }

    public void setSessionDn(String sessionDn) {
        this.sessionDn = sessionDn;
    }

    public boolean isFromCache() {
        return isFromCache;
    }

    public void setIsFromCache(boolean isFromCache) {
        this.isFromCache = isFromCache;
    }

    public final void setFromCache(boolean isFromCache) {
        this.isFromCache = isFromCache;
    }

    public boolean isImplicitFlow() {
        return StringUtils.isBlank(grantType) || grantType.equals(GrantType.IMPLICIT.getValue());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TokenLdap tokenLdap = (TokenLdap) o;

        if (tokenCode != null ? !tokenCode.equals(tokenLdap.tokenCode) : tokenLdap.tokenCode != null) return false;
        if (tokenType != null ? !tokenType.equals(tokenLdap.tokenType) : tokenLdap.tokenType != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = tokenCode != null ? tokenCode.hashCode() : 0;
        result = 31 * result + (tokenType != null ? tokenType.hashCode() : 0);
        return result;
    }
}
