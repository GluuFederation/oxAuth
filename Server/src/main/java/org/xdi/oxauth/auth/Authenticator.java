/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.auth;

import org.apache.commons.lang.StringUtils;
import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.contexts.Context;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.core.Events;
import org.jboss.seam.faces.FacesManager;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.international.StatusMessage.Severity;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.SimplePrincipal;
import org.xdi.model.AuthenticationScriptUsageType;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.common.SessionIdState;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.Constants;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.service.AuthenticationService;
import org.xdi.oxauth.service.ClientService;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.oxauth.util.ServerUtil;
import org.xdi.util.StringHelper;

import javax.faces.context.ExternalContext;
import java.io.Serializable;
import java.security.Principal;
import java.util.List;
import java.util.Map;

/**
 * Authenticator component
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
@Name("authenticator")
@Scope(ScopeType.EVENT)
// Do not change scope, we try to keep server without http sessions
public class Authenticator implements Serializable {

    private static final long serialVersionUID = 669395320060928092L;

    @Logger
    private Log log;

    @In
    private Identity identity;

    @In
    private ClientService clientService;

    @In
    private SessionIdService sessionIdService;

    @In
    private AuthenticationService authenticationService;

    @In
    private ExternalAuthenticationService externalAuthenticationService;

    @In
    private AppConfiguration appConfiguration;

    @In
    private FacesMessages facesMessages;

    @In(value = "#{facesContext.externalContext}", required = false)
    private ExternalContext externalContext;

    private String authAcr;

    private Integer authStep;

    private boolean addedErrorMessage;

    /**
     * Tries to authenticate an user, returns <code>true</code> if the
     * authentication succeed
     *
     * @return Returns <code>true</code> if the authentication succeed
     */
    public boolean authenticate() {
        if (!authenticateImpl(Contexts.getEventContext(), true, false)) {
            return authenticationFailed();
        } else {
            return true;
        }
    }

    public String authenticateWithOutcome() {
        boolean result = authenticateImpl(Contexts.getEventContext(), true, false);
        if (result) {
            return Constants.RESULT_SUCCESS;
        } else {
            return Constants.RESULT_FAILURE;
        }

    }

    public boolean authenticateWebService(boolean skipPassword) {
        return authenticateImpl(getWebServiceContext(), false, skipPassword);
    }

    public boolean authenticateWebService() {
        return authenticateImpl(getWebServiceContext(), false, false);
    }

    public Context getWebServiceContext() {
        return Contexts.getEventContext();
    }

    public boolean authenticateImpl(Context context, boolean interactive, boolean skipPassword) {
        Credentials credentials = ServerUtil.instance(Credentials.class);
        boolean authenticated = false;
        try {
            log.trace("Authenticating ... (interactive: " + interactive + ", skipPassword: " + skipPassword + ", credentials.username: " + credentials.getUsername() + ")");
            if (StringHelper.isNotEmpty(credentials.getUsername()) && (skipPassword || StringHelper.isNotEmpty(credentials.getPassword()))
                    && credentials.getUsername().startsWith("@!")) {
                authenticated = clientAuthentication(credentials, context, interactive, skipPassword);
            } else {
                if (interactive) {
                    authenticated = userAuthenticationInteractive(credentials);
                } else {
                    authenticated = userAuthenticationService(credentials);
                }
            }
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }

        if (authenticated) {
            log.trace("Authentication successfully for '{0}'", credentials.getUsername());
            return true;
        }

        log.info("Authentication failed for '{0}'", credentials.getUsername());
        return false;
    }

    private boolean clientAuthentication(Credentials credentials, Context context, boolean interactive, boolean skipPassword) {
        boolean isServiceUsesExternalAuthenticator = !interactive && externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.SERVICE);
        if (isServiceUsesExternalAuthenticator) {
            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService
                    .determineCustomScriptConfiguration(AuthenticationScriptUsageType.SERVICE, 1, this.authAcr);

            if (customScriptConfiguration == null) {
                log.error("Failed to get CustomScriptConfiguration. acr: '{0}'", this.authAcr);
            } else {
                this.authAcr = customScriptConfiguration.getCustomScript().getName();

                boolean result = externalAuthenticationService.executeExternalAuthenticate(customScriptConfiguration, null, 1);
                log.info("Authentication result for user '{0}', result: '{1}'", credentials.getUsername(), result);

                if (result) {
                    authenticationService.configureSessionClient(context);

                    log.info("Authentication success for client: '{0}'", credentials.getUsername());
                    return true;
                }
            }
        }

        boolean loggedIn = skipPassword;
        if (!loggedIn) {
            loggedIn = clientService.authenticate(credentials.getUsername(), credentials.getPassword());
        }
        if (loggedIn) {
            authenticationService.configureSessionClient(context);

            log.info("Authentication success for Client: '{0}'", credentials.getUsername());
            return true;
        }

        return false;
    }

    private boolean userAuthenticationInteractive(Credentials credentials) {
        SessionId sessionId = sessionIdService.getSessionId();
        Map<String, String> sessionIdAttributes = sessionIdService.getSessionAttributes(sessionId);
        if (sessionIdAttributes == null) {
            log.error("Failed to get session attributes");
            authenticationFailedSessionInvalid();
            return false;
        }

        // Set in event context sessionAttributes to allow access them from external authenticator
        Context eventContext = Contexts.getEventContext();
        eventContext.set("sessionAttributes", sessionIdAttributes);

        initCustomAuthenticatorVariables(sessionIdAttributes);
        boolean useExternalAuthenticator = externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.INTERACTIVE);
        if (useExternalAuthenticator && !StringHelper.isEmpty(this.authAcr)) {
            initCustomAuthenticatorVariables(sessionIdAttributes);
            if ((this.authStep == null) || StringHelper.isEmpty(this.authAcr)) {
                log.error("Failed to determine authentication mode");
                authenticationFailedSessionInvalid();
                return false;
            }

            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService.getCustomScriptConfiguration(AuthenticationScriptUsageType.INTERACTIVE, this.authAcr);
            if (customScriptConfiguration == null) {
                log.error("Failed to get CustomScriptConfiguration for acr: '{1}', auth_step: '{0}'", this.authAcr, this.authStep);
                return false;
            }

            // Check if all previous steps had passed
            boolean passedPreviousSteps = isPassedPreviousAuthSteps(sessionIdAttributes, this.authStep);
            if (!passedPreviousSteps) {
                log.error("There are authentication steps not marked as passed. acr: '{1}', auth_step: '{0}'", this.authAcr, this.authStep);
                return false;
            }

            boolean result = externalAuthenticationService.executeExternalAuthenticate(customScriptConfiguration, externalContext.getRequestParameterValuesMap(), this.authStep);
            log.debug("Authentication result for user '{0}'. auth_step: '{1}', result: '{2}', credentials: '{3}'", credentials.getUsername(), this.authStep, result, System.identityHashCode(credentials));

            int overridenNextStep = -1;

            int apiVersion = externalAuthenticationService.executeExternalGetApiVersion(customScriptConfiguration);
            if (apiVersion > 1) {
                log.trace("According to API version script supports steps overriding");
                overridenNextStep = externalAuthenticationService.getNextStep(customScriptConfiguration, externalContext.getRequestParameterValuesMap(), this.authStep);
                log.debug("Get next step from script: '{0}'", apiVersion);
            }

            if (!result && (overridenNextStep == -1)) {
                return false;
            }

            boolean overrideCurrentStep = false;
            if (overridenNextStep > -1) {
                overrideCurrentStep = true;
                // Reload session id
                sessionId = sessionIdService.getSessionId();

                // Reset to pecified step
                sessionIdService.resetToStep(sessionId, overridenNextStep);

                this.authStep = overridenNextStep;
                log.info("Authentication reset to step : '{0}'", this.authStep);
            }


            // Update parameters map to allow access it from count authentication steps method
            updateExtraParameters(customScriptConfiguration, this.authStep + 1, sessionIdAttributes);

            // Determine count authentication methods
            int countAuthenticationSteps = externalAuthenticationService.executeExternalGetCountAuthenticationSteps(customScriptConfiguration);

            // Reload from LDAP to make sure that we are updating latest session attributes
            sessionId = sessionIdService.getSessionId();
            sessionIdAttributes = sessionIdService.getSessionAttributes(sessionId);

            // Prepare for next step
            if ((this.authStep < countAuthenticationSteps) || overrideCurrentStep) {
                int nextStep;
                if (overrideCurrentStep) {
                    nextStep = overridenNextStep;
                } else {
                    nextStep = this.authStep + 1;
                }

                String redirectTo = externalAuthenticationService.executeExternalGetPageForStep(customScriptConfiguration, nextStep);
                if (StringHelper.isEmpty(redirectTo)) {
                    redirectTo = "/login.xhtml";
                }

                // Store/Update extra parameters in session attributes map
                updateExtraParameters(customScriptConfiguration, nextStep, sessionIdAttributes);

                if (!overrideCurrentStep) {
                    // Update auth_step
                    sessionIdAttributes.put("auth_step", Integer.toString(nextStep));

                    // Mark step as passed
                    markAuthStepAsPassed(sessionIdAttributes, this.authStep);
                }

                if (sessionId != null) {
                    boolean updateResult = updateSession(sessionId, sessionIdAttributes);
                    if (!updateResult) {
                        return false;
                    }
                }

                log.trace("Redirect to page: '{0}'", redirectTo);
                FacesManager.instance().redirect(redirectTo, null, false);
                return true;
            }

            if (this.authStep == countAuthenticationSteps) {
                SessionId eventSessionId = authenticationService.configureSessionUser(sessionId, sessionIdAttributes);

                Principal principal = new SimplePrincipal(credentials.getUsername());
                identity.acceptExternallyAuthenticatedPrincipal(principal);
                identity.quietLogin();

                // Redirect to authorization workflow
                if (Events.exists()) {
                    log.debug("Sending event to trigger user redirection: '{0}'", credentials.getUsername());
                    authenticationService.onSuccessfulLogin(eventSessionId);
//                    Events.instance().raiseEvent(Constants.EVENT_OXAUTH_CUSTOM_LOGIN_SUCCESSFUL);
                }

                log.info("Authentication success for User: '{0}'", credentials.getUsername());
                return true;
            }
        } else {
            if (StringHelper.isNotEmpty(credentials.getUsername())) {
                boolean authenticated = authenticationService.authenticate(credentials.getUsername(), credentials.getPassword());
                if (authenticated) {
                    SessionId eventSessionId = authenticationService.configureSessionUser(sessionId, sessionIdAttributes);

                    // Redirect to authorization workflow
                    if (Events.exists()) {
                        log.debug("Sending event to trigger user redirection: '{0}'", credentials.getUsername());
                        authenticationService.onSuccessfulLogin(eventSessionId);
//                        Events.instance().raiseEvent(Constants.EVENT_OXAUTH_CUSTOM_LOGIN_SUCCESSFUL);
                    }

                    log.info("Authentication success for User: '{0}'", credentials.getUsername());
                    return true;
                }
            }
        }

        return false;
    }

    private boolean updateSession(SessionId sessionId, Map<String, String> sessionIdAttributes) {
        sessionId.setSessionAttributes(sessionIdAttributes);
        boolean updateResult = sessionIdService.updateSessionId(sessionId, true, true, true);
        if (!updateResult) {
            log.debug("Failed to update session entry: '{0}'", sessionId.getId());
            return false;
        }

        return true;
    }

    private boolean userAuthenticationService(Credentials credentials) {
        if (externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.SERVICE)) {
            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService
                    .determineCustomScriptConfiguration(AuthenticationScriptUsageType.SERVICE, 1, this.authAcr);

            if (customScriptConfiguration == null) {
                log.error("Failed to get CustomScriptConfiguration. auth_step: '{0}', acr: '{1}'",
                        this.authStep, this.authAcr);
            } else {
                this.authAcr = customScriptConfiguration.getName();

                boolean result = externalAuthenticationService.executeExternalAuthenticate(customScriptConfiguration, null, 1);
                log.info("Authentication result for '{0}'. auth_step: '{1}', result: '{2}'", credentials.getUsername(), this.authStep, result);

                if (result) {
                    authenticateExternallyWebService(credentials.getUsername());
                    authenticationService.configureEventUser();

                    log.info("Authentication success for User: '{0}'", credentials.getUsername());
                    return true;
                }
                log.info("Authentication failed for User: '{0}'", credentials.getUsername());
            }
        }

        if (StringHelper.isNotEmpty(credentials.getUsername())) {
            boolean authenticated = authenticationService.authenticate(credentials.getUsername(), credentials.getPassword());
            if (authenticated) {
                authenticateExternallyWebService(credentials.getUsername());
                authenticationService.configureEventUser();

                log.info("Authentication success for User: '{0}'", credentials.getUsername());
                return true;
            }
            log.info("Authentication failed for User: '{0}'", credentials.getUsername());
        }

        return false;
    }

    private void updateExtraParameters(CustomScriptConfiguration customScriptConfiguration, final int step, Map<String, String> sessionIdAttributes) {
        List<String> extraParameters = externalAuthenticationService.executeExternalGetExtraParametersForStep(customScriptConfiguration, step);
        if (extraParameters != null) {
            for (String extraParameter : extraParameters) {
                if (authenticationService.isParameterExists(extraParameter)) {
                    String extraParameterValue = authenticationService.getParameterValue(extraParameter);
                    sessionIdAttributes.put(extraParameter, extraParameterValue);
                }
            }
        }
    }

    public String prepareAuthenticationForStep() {
        SessionId sessionId = sessionIdService.getSessionId();
        Map<String, String> sessionIdAttributes = sessionIdService.getSessionAttributes(sessionId);
        if (sessionIdAttributes == null) {
            log.error("Failed to get attributes from session");
            return Constants.RESULT_EXPIRED;
        }

        // Set in event context sessionAttributs to allow access them from external authenticator
        Context eventContext = Contexts.getEventContext();
        eventContext.set("sessionAttributes", sessionIdAttributes);

        if (!externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.INTERACTIVE)) {
            return Constants.RESULT_SUCCESS;
        }

        initCustomAuthenticatorVariables(sessionIdAttributes);
        if (StringHelper.isEmpty(this.authAcr)) {
            return Constants.RESULT_SUCCESS;
        }

        if ((this.authStep == null) || (this.authStep < 1)) {
            return Constants.RESULT_NO_PERMISSIONS;
        }

        CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService.getCustomScriptConfiguration(
                AuthenticationScriptUsageType.INTERACTIVE, this.authAcr);
        if (customScriptConfiguration == null) {
            log.error("Failed to get CustomScriptConfiguration. auth_step: '{0}', acr: '{1}'", this.authStep, this.authAcr);
            return Constants.RESULT_FAILURE;
        }

        String currentauthAcr = customScriptConfiguration.getName();

        customScriptConfiguration = externalAuthenticationService.determineExternalAuthenticatorForWorkflow(
                AuthenticationScriptUsageType.INTERACTIVE, customScriptConfiguration);
        if (customScriptConfiguration == null) {
            return Constants.RESULT_FAILURE;
        } else {
            String determinedauthAcr = customScriptConfiguration.getName();
            if (!StringHelper.equalsIgnoreCase(currentauthAcr, determinedauthAcr)) {
                // Redirect user to alternative login workflow
                String redirectTo = externalAuthenticationService.executeExternalGetPageForStep(customScriptConfiguration, this.authStep);

                if (StringHelper.isEmpty(redirectTo)) {
                    redirectTo = "/login.xhtml";
                }

                CustomScriptConfiguration determinedCustomScriptConfiguration = externalAuthenticationService.getCustomScriptConfiguration(
                        AuthenticationScriptUsageType.INTERACTIVE, determinedauthAcr);
                if (determinedCustomScriptConfiguration == null) {
                    log.error("Failed to get determined CustomScriptConfiguration. auth_step: '{0}', acr: '{1}'", this.authStep, this.authAcr);
                    return Constants.RESULT_FAILURE;
                }

                log.debug("Redirect to page: '{0}'. Force to use acr: '{1}'", redirectTo, determinedauthAcr);

                determinedauthAcr = determinedCustomScriptConfiguration.getName();
                String determinedAuthLevel = Integer.toString(determinedCustomScriptConfiguration.getLevel());

                sessionIdAttributes.put("acr", determinedauthAcr);
                sessionIdAttributes.put("auth_level", determinedAuthLevel);
                sessionIdAttributes.put("auth_step", Integer.toString(1));

                if (sessionId != null) {
                    boolean updateResult = updateSession(sessionId, sessionIdAttributes);
                    if (!updateResult) {
                        return Constants.RESULT_EXPIRED;
                    }
                }

                FacesManager.instance().redirect(redirectTo, null, false);

                return Constants.RESULT_SUCCESS;
            }
        }

        // Check if all previous steps had passed
        boolean passedPreviousSteps = isPassedPreviousAuthSteps(sessionIdAttributes, this.authStep);
        if (!passedPreviousSteps) {
            log.error("There are authentication steps not marked as passed. acr: '{1}', auth_step: '{0}'", this.authAcr, this.authStep);
            return Constants.RESULT_FAILURE;
        }

        Boolean result = externalAuthenticationService.executeExternalPrepareForStep(customScriptConfiguration, externalContext.getRequestParameterValuesMap(), this.authStep);
        if ((result != null) && result) {
            // Store/Update extra parameters in session attributes map
            updateExtraParameters(customScriptConfiguration, this.authStep, sessionIdAttributes);

            if (sessionId != null) {
                boolean updateResult = updateSession(sessionId, sessionIdAttributes);
                if (!updateResult) {
                    return Constants.RESULT_FAILURE;
                }
            }

            return Constants.RESULT_SUCCESS;
        } else {
            return Constants.RESULT_FAILURE;
        }
    }

    public void authenticateExternallyWebService(String userName) {
        org.jboss.seam.resteasy.Application application = (org.jboss.seam.resteasy.Application) Component.getInstance(org.jboss.seam.resteasy.Application.class);
        if ((application != null) && !application.isDestroySessionAfterRequest()) {
            Principal principal = new SimplePrincipal(userName);
            identity.acceptExternallyAuthenticatedPrincipal(principal);
            identity.quietLogin();
        }
    }

    public boolean authenticateBySessionId(String p_sessionId) {
        if (StringUtils.isNotBlank(p_sessionId) && appConfiguration.getSessionIdEnabled()) {
            try {
                SessionId sessionId = sessionIdService.getSessionId(p_sessionId);
                return authenticateBySessionId(sessionId);
            } catch (Exception e) {
                log.trace(e.getMessage(), e);
            }
        }

        return false;
    }

    public boolean authenticateBySessionId(SessionId sessionId) {
        if (sessionId == null) {
            return false;
        }
        String p_sessionId = sessionId.getId();

        log.trace("authenticateBySessionId, sessionId = '{0}', session = '{1}', state= '{2}'", p_sessionId, sessionId, sessionId.getState());
        // IMPORTANT : authenticate by session id only if state of session is authenticated!
        if (SessionIdState.AUTHENTICATED == sessionId.getState()) {
            final User user = authenticationService.getUserOrRemoveSession(sessionId);
            if (user != null) {
                try {
                    authenticateExternallyWebService(user.getUserId());
                    authenticationService.configureEventUser(sessionId);
                } catch (Exception e) {
                    log.trace(e.getMessage(), e);
                }

                return true;
            }
        }

        return false;
    }

    private void initCustomAuthenticatorVariables(Map<String, String> sessionIdAttributes) {
        if (sessionIdAttributes == null) {
            log.error("Failed to restore attributes from session attributes");
            return;
        }

        this.authStep = StringHelper.toInteger(sessionIdAttributes.get("auth_step"), null);
        this.authAcr = sessionIdAttributes.get(JwtClaimName.AUTHENTICATION_CONTEXT_CLASS_REFERENCE);
    }

    private boolean authenticationFailed() {
        if (!this.addedErrorMessage) {
            facesMessages.addFromResourceBundle(Severity.ERROR, "login.errorMessage");
        }
        return false;
    }

    private void authenticationFailedSessionInvalid() {
        this.addedErrorMessage = true;
        facesMessages.addFromResourceBundle(Severity.ERROR, "login.errorSessionInvalidMessage");
        FacesManager.instance().redirect("/error.xhtml");
    }

    private void markAuthStepAsPassed(Map<String, String> sessionIdAttributes, Integer authStep) {
        String key = String.format("auth_step_passed_%d", authStep);
        sessionIdAttributes.put(key, Boolean.TRUE.toString());
    }

    private boolean isAuthStepPassed(Map<String, String> sessionIdAttributes, Integer authStep) {
        String key = String.format("auth_step_passed_%d", authStep);
        if (sessionIdAttributes.containsKey(key) && Boolean.parseBoolean(sessionIdAttributes.get(key))) {
            return true;
        }

        return false;
    }

    private boolean isPassedPreviousAuthSteps(Map<String, String> sessionIdAttributes, Integer authStep) {
        for (int i = 1; i < authStep; i++) {
            boolean isAuthStepPassed = isAuthStepPassed(sessionIdAttributes, i);
            if (!isAuthStepPassed) {
                return false;
            }
        }

        return true;
    }

    public void configureSessionClient(Client client) {
        authenticationService.configureSessionClient(getWebServiceContext(), client);
    }

}