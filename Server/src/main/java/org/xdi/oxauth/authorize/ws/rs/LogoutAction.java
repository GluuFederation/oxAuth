/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.authorize.ws.rs;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.faces.FacesManager;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.international.StatusMessage.Severity;
import org.jboss.seam.log.Log;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.oxauth.model.common.AuthorizationGrant;
import org.xdi.oxauth.model.common.AuthorizationGrantList;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.session.EndSessionRequestParam;
import org.xdi.oxauth.model.util.Base64Util;
import org.xdi.oxauth.model.util.Util;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.service.JsonService;
import org.xdi.util.StringHelper;

import java.io.IOException;
import java.util.Map;

/**
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
@Name("logoutAction")
@Scope(ScopeType.EVENT)
public class LogoutAction {

    private static final String EXTERNAL_LOGOUT = "external_logout";
    private static final String EXTERNAL_LOGOUT_DATA = "external_logout_data";

    @Logger
    private Log log;

    @In
    private FacesMessages facesMessages;

    @In
    private AuthorizationGrantList authorizationGrantList;

    @In
    private SessionIdService sessionIdService;

    @In
    private ExternalAuthenticationService externalAuthenticationService;

    @In
    private JsonService jsonService;

    @In
    private AppConfiguration appConfiguration;

    private String idTokenHint;
    private String postLogoutRedirectUri;
    private SessionId sessionId;


    public String getIdTokenHint() {
        return idTokenHint;
    }

    public void setIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }

    public void redirect() {
        SessionId sessionId = sessionIdService.getSessionId();

        boolean validationResult = validateParameters();
        if (!validationResult) {
            try {
                restoreLogoutParametersFromSession(sessionId);
            } catch (IOException ex) {
                logoutFailed();
                log.debug("Failed to restore logout parameters from session", ex);
            }

            validationResult = validateParameters();
            if (!validationResult) {
                missingLogoutParameters();
                return;
            }
        }

        ExternalLogoutResult externalLogoutResult = processExternalAuthenticatorLogOut(sessionId);
        if (ExternalLogoutResult.FAILURE == externalLogoutResult) {
            logoutFailed();
            return;
        } else if (ExternalLogoutResult.REDIRECT == externalLogoutResult) {
            return;
        }

        StringBuilder sb = new StringBuilder();

        // Required parameters
        if (idTokenHint != null && !idTokenHint.isEmpty()) {
            sb.append(EndSessionRequestParam.ID_TOKEN_HINT + "=").append(idTokenHint);
        }

        if (sessionId != null && !postLogoutRedirectUri.isEmpty()) {
            sb.append("&" + EndSessionRequestParam.SESSION_ID + "=").append(sessionId.getId());
        }

        if (postLogoutRedirectUri != null && !postLogoutRedirectUri.isEmpty()) {
            sb.append("&" + EndSessionRequestParam.POST_LOGOUT_REDIRECT_URI + "=").append(postLogoutRedirectUri);
        }

        FacesManager.instance().redirectToExternalURL("seam/resource/restv1/oxauth/end_session?" + sb.toString());
    }

    private boolean validateParameters() {
        return (StringHelper.isNotEmpty(idTokenHint) || (sessionId != null)) && StringHelper.isNotEmpty(postLogoutRedirectUri);
    }

    private ExternalLogoutResult processExternalAuthenticatorLogOut(SessionId sessionId) {
        if ((sessionId != null) && sessionId.getSessionAttributes().containsKey(EXTERNAL_LOGOUT)) {
            log.debug("Detected callback from external system. Resuming logout.");
            return ExternalLogoutResult.SUCCESS;
        }

        AuthorizationGrant authorizationGrant = authorizationGrantList.getAuthorizationGrantByIdToken(idTokenHint);
        if (authorizationGrant == null) {
            Boolean endSessionWithAccessToken = appConfiguration.getEndSessionWithAccessToken();
            if ((endSessionWithAccessToken != null) && endSessionWithAccessToken) {
                authorizationGrant = authorizationGrantList.getAuthorizationGrantByAccessToken(idTokenHint);
            }
        }
        if ((authorizationGrant == null) && (sessionId == null)) {
            return ExternalLogoutResult.FAILURE;
        }

        String acrValues;
        if (authorizationGrant == null) {
            acrValues = sessionIdService.getAcr(sessionId);
        } else {
            acrValues = authorizationGrant.getAcrValues();
        }

        boolean isExternalAuthenticatorLogoutPresent = StringHelper.isNotEmpty(acrValues);
        if (isExternalAuthenticatorLogoutPresent) {
            log.debug("Attemptinmg to execute logout method of '{0}' external authenticator.", acrValues);

            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService.getCustomScriptConfigurationByName(acrValues);
            if (customScriptConfiguration == null) {
                log.error("Failed to get ExternalAuthenticatorConfiguration. acr_values: {0}", acrValues);
                return ExternalLogoutResult.FAILURE;
            } else {
                boolean scriptExternalLogoutResult = externalAuthenticationService.executeExternalLogout(customScriptConfiguration, null);
                ExternalLogoutResult externalLogoutResult = scriptExternalLogoutResult ? ExternalLogoutResult.SUCCESS : ExternalLogoutResult.FAILURE;
                log.debug("Logout result is '{0}' for session '{1}', userDn: '{2}'", externalLogoutResult, sessionId.getId(), sessionId.getUserDn());

                int apiVersion = externalAuthenticationService.executeExternalGetApiVersion(customScriptConfiguration);
                if (apiVersion < 3) {
                    // Not support redirect to external system at logout
                    return externalLogoutResult;
                }

                log.trace("According to API version script supports logout redirects");
                String logoutExternalUrl = externalAuthenticationService.getLogoutExternalUrl(customScriptConfiguration, null);
                log.debug("External logout result is '{0}' for user '{1}'", logoutExternalUrl, sessionId.getUserDn());

                if (StringHelper.isEmpty(logoutExternalUrl)) {
                    return externalLogoutResult;
                }

                // Store in session parameters needed to call end_session
                try {
                    storeLogoutParametersInSession(sessionId);
                } catch (IOException ex) {
                    log.debug("Failed to persist logout parameters in session", ex);

                    return ExternalLogoutResult.FAILURE;
                }

                // Redirect to external URL
                FacesManager.instance().redirectToExternalURL(logoutExternalUrl);
                return ExternalLogoutResult.REDIRECT;
            }
        } else {
            return ExternalLogoutResult.SUCCESS;
        }
    }

    private void storeLogoutParametersInSession(SessionId sessionId) throws JsonGenerationException, JsonMappingException, IOException {
        Map<String, String> sessionAttributes = sessionId.getSessionAttributes();

        LogoutParameters logoutParameters = new LogoutParameters(idTokenHint, postLogoutRedirectUri);

        String logoutParametersJson = jsonService.objectToJson(logoutParameters);
        String logoutParametersBase64 = Base64Util.base64urlencode(logoutParametersJson.getBytes(Util.UTF8_STRING_ENCODING));

        sessionAttributes.put(EXTERNAL_LOGOUT, Boolean.toString(true));
        sessionAttributes.put(EXTERNAL_LOGOUT_DATA, logoutParametersBase64);

        sessionIdService.updateSessionId(sessionId);
    }

    private boolean restoreLogoutParametersFromSession(SessionId sessionId) throws IllegalArgumentException, JsonParseException, JsonMappingException, IOException {
        if (sessionId == null) {
            return false;
        }

        this.sessionId = sessionId;
        Map<String, String> sessionAttributes = sessionId.getSessionAttributes();

        boolean restoreParameters = sessionAttributes.containsKey(EXTERNAL_LOGOUT);
        if (!restoreParameters) {
            return false;
        }

        String logoutParametersBase64 = sessionAttributes.get(EXTERNAL_LOGOUT_DATA);
        String logoutParametersJson = new String(Base64Util.base64urldecode(logoutParametersBase64), Util.UTF8_STRING_ENCODING);

        LogoutParameters logoutParameters = jsonService.jsonToObject(logoutParametersJson, LogoutParameters.class);

        this.idTokenHint = logoutParameters.getIdTokenHint();
        this.postLogoutRedirectUri = logoutParameters.getPostLogoutRedirectUri();

        return true;
    }

    public void missingLogoutParameters() {
        facesMessages.addFromResourceBundle(Severity.ERROR, "logout.missingParameters");
        FacesManager.instance().redirect("/error.xhtml");
    }

    public void logoutFailed() {
        facesMessages.add(Severity.ERROR, "Failed to process logout");
        FacesManager.instance().redirect("/error.xhtml");
    }


    public static class LogoutParameters {
        private String idTokenHint;
        private String postLogoutRedirectUri;

        public LogoutParameters() {
        }

        public LogoutParameters(String idTokenHint, String postLogoutRedirectUri) {
            this.idTokenHint = idTokenHint;
            this.postLogoutRedirectUri = postLogoutRedirectUri;
        }

        public String getIdTokenHint() {
            return idTokenHint;
        }

        public void setIdTokenHint(String idTokenHint) {
            this.idTokenHint = idTokenHint;
        }

        public String getPostLogoutRedirectUri() {
            return postLogoutRedirectUri;
        }

        public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
            this.postLogoutRedirectUri = postLogoutRedirectUri;
        }

    }

    private enum ExternalLogoutResult {
        SUCCESS,
        FAILURE,
        REDIRECT
    }

}