package org.gluu.oxauth.model.common;

import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.ldap.TokenLdap;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.service.AttributeService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Yuriy Zabrovarnyy
 */
public class ExecutionContext {

    private final HttpServletRequest httpRequest;
    private final HttpServletResponse httpResponse;

    private Client client;
    private AuthorizationGrant grant;

    private TokenLdap idTokenEntity;
    private TokenLdap accessTokenEntity;
    private TokenLdap refreshTokenEntity;

    private AppConfiguration appConfiguration;
    private AttributeService attributeService;

    private int refreshTokenLifetimeFromScript;

    public ExecutionContext(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        this.httpRequest = httpRequest;
        this.httpResponse = httpResponse;
    }

    public int getRefreshTokenLifetimeFromScript() {
        return refreshTokenLifetimeFromScript;
    }

    public void setRefreshTokenLifetimeFromScript(int refreshTokenLifetimeFromScript) {
        this.refreshTokenLifetimeFromScript = refreshTokenLifetimeFromScript;
    }

    public HttpServletRequest getHttpRequest() {
        return httpRequest;
    }

    public HttpServletResponse getHttpResponse() {
        return httpResponse;
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public AuthorizationGrant getGrant() {
        return grant;
    }

    public void setGrant(AuthorizationGrant grant) {
        this.grant = grant;
    }

    public TokenLdap getIdTokenEntity() {
        return idTokenEntity;
    }

    public void setIdTokenEntity(TokenLdap idTokenEntity) {
        this.idTokenEntity = idTokenEntity;
    }

    public TokenLdap getAccessTokenEntity() {
        return accessTokenEntity;
    }

    public void setAccessTokenEntity(TokenLdap accessTokenEntity) {
        this.accessTokenEntity = accessTokenEntity;
    }

    public TokenLdap getRefreshTokenEntity() {
        return refreshTokenEntity;
    }

    public void setRefreshTokenEntity(TokenLdap refreshTokenEntity) {
        this.refreshTokenEntity = refreshTokenEntity;
    }

    public AppConfiguration getAppConfiguration() {
        return appConfiguration;
    }

    public void setAppConfiguration(AppConfiguration appConfiguration) {
        this.appConfiguration = appConfiguration;
    }

    public AttributeService getAttributeService() {
        return attributeService;
    }

    public void setAttributeService(AttributeService attributeService) {
        this.attributeService = attributeService;
    }
}
