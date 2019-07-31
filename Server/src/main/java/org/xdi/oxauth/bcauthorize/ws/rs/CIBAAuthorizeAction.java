/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.bcauthorize.ws.rs;

import org.gluu.jsf2.message.FacesMessages;
import org.gluu.jsf2.service.FacesService;
import org.slf4j.Logger;
import org.xdi.oxauth.client.push.PushTokenDeliveryClient;
import org.xdi.oxauth.client.push.PushTokenDeliveryRequest;
import org.xdi.oxauth.client.push.PushTokenDeliveryResponse;
import org.xdi.oxauth.model.authorize.ScopeChecker;
import org.xdi.oxauth.model.common.AuthorizationGrantList;
import org.xdi.oxauth.model.common.CIBAGrant;
import org.xdi.oxauth.model.common.Scope;
import org.xdi.oxauth.model.common.TokenType;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.model.util.StringUtils;
import org.xdi.oxauth.service.AuthorizeService;
import org.xdi.oxauth.service.ClientService;

import javax.enterprise.context.RequestScoped;
import javax.faces.application.FacesMessage;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2019
 */
@RequestScoped
@Named("cibaAuthorizeAction")
public class CIBAAuthorizeAction {

    @Inject
    private Logger log;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private ClientService clientService;

    @Inject
    private AuthorizeService authorizeService;

    @Inject
    private ScopeChecker scopeChecker;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Inject
    private FacesService facesService;

    @Inject
    private FacesMessages facesMessages;

    private String authorizationRequestId;

    private Client client;

    private CIBAGrant authorizationGrant;

    public void loadAuthorizationGrant() {
        if (authorizationRequestId != null && !authorizationRequestId.isEmpty() && authorizationGrant == null) {
            authorizationGrant = authorizationGrantList.getCIBAGrant(authorizationRequestId);
        }
    }

    public Client getClient() {
        if (authorizationGrant != null && client == null) {
            String clientId = authorizationGrant.getClientId();

            client = clientService.getClient(clientId);
        }

        return client;
    }

    public List<Scope> getScopes() {
        Set<String> scope = new HashSet<>();

        if (authorizationGrant != null) {
            scope = authorizationGrant.getScopes();
        }

        Set<String> grantedScopes = scopeChecker.checkScopesPolicy(getClient(), StringUtils.implode(scope, " "));
        String allowedScope = StringUtils.implode(grantedScopes, " ");
        return authorizeService.getScopes(allowedScope);
    }

    public void permissionGranted() {
        loadAuthorizationGrant();

        if ((authorizationRequestId == null) || authorizationRequestId.isEmpty()) {
            log.error("Permission denied. auth_req_id should be not empty.");
            permissionDenied();
            return;
        }

        if (getClient() == null) {
            log.error("Permission denied. Failed to find the client in LDAP.");
            permissionDenied();
            return;
        }

        authorizationGrant.setUserAuthorization(true);
        authorizationGrant.save();

        PushTokenDeliveryRequest pushTokenDeliveryRequest = new PushTokenDeliveryRequest();

        //pushTokenDeliveryRequest.setClientNotificationToken(authorizationGrant.getClientNotificationToken());
        pushTokenDeliveryRequest.setAuthorizationRequestId(authorizationGrant.getCIBAAuthenticationRequestId().getCode());
        //pushTokenDeliveryRequest.setAccessToken(authorizationGrant.getAccessToken());
        pushTokenDeliveryRequest.setTokenType(TokenType.BEARER);
        pushTokenDeliveryRequest.setRefreshToken(null);
        pushTokenDeliveryRequest.setExpiresIn(3600);
        pushTokenDeliveryRequest.setIdToken(null);

        String clientNotificationEndpoint = "https://ce.gluu.info/oxauth-ciba-client-test/client-notification-endpoint"; //authorizationGrant.getClientNotificationEndpoint();

        PushTokenDeliveryClient pushTokenDeliveryClient = new PushTokenDeliveryClient(clientNotificationEndpoint);
        pushTokenDeliveryClient.setRequest(pushTokenDeliveryRequest);
        PushTokenDeliveryResponse pushTokenDeliveryResponse = pushTokenDeliveryClient.exec();

        facesMessages.add(FacesMessage.SEVERITY_INFO, "Permission granted.");
        facesService.redirect("/ciba/authorizeResponse.xhtml");
    }

    public void permissionDenied() {
        loadAuthorizationGrant();

        authorizationGrant.setUserAuthorization(false);
        authorizationGrant.save();

        facesMessages.add(FacesMessage.SEVERITY_INFO, "Permission denied.");
        facesService.redirect("/ciba/authorizeResponse.xhtml");
    }

    public String getAuthorizationRequestId() {
        return authorizationRequestId;
    }

    public void setAuthorizationRequestId(String authorizationRequestId) {
        this.authorizationRequestId = authorizationRequestId;
    }

    public String getApiKey() {
        return appConfiguration.getCibaEndUserNotificationConfig().getApiKey();
    }

    public String getAuthDomain() {
        return appConfiguration.getCibaEndUserNotificationConfig().getAuthDomain();
    }

    public String getDatabaseURL() {
        return appConfiguration.getCibaEndUserNotificationConfig().getDatabaseURL();
    }

    public String getProjectId() {
        return appConfiguration.getCibaEndUserNotificationConfig().getProjectId();
    }

    public String getStorageBucket() {
        return appConfiguration.getCibaEndUserNotificationConfig().getStorageBucket();
    }

    public String getMessagingSenderId() {
        return appConfiguration.getCibaEndUserNotificationConfig().getMessagingSenderId();
    }

    public String getAppId() {
        return appConfiguration.getCibaEndUserNotificationConfig().getAppId();
    }

    public String getPublicVapidKey() {
        return appConfiguration.getCibaEndUserNotificationConfig().getPublicVapidKey();
    }

    public String getBackchannelDeviceRegistrationEndpoint() {
        return appConfiguration.getBackchannelDeviceRegistrationEndpoint();
    }
}
