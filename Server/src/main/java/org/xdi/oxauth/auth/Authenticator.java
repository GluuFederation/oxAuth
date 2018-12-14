/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.auth;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.enterprise.context.RequestScoped;
import javax.faces.application.FacesMessage;
import javax.faces.application.FacesMessage.Severity;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.gluu.jsf2.message.FacesMessages;
import org.gluu.jsf2.service.FacesService;
import org.slf4j.Logger;
import org.xdi.model.AuthenticationScriptUsageType;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.model.security.Credentials;
import org.xdi.oxauth.i18n.LanguageBean;
import org.xdi.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.common.SessionIdState;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.Constants;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.model.util.Util;
import org.xdi.oxauth.security.Identity;
import org.xdi.oxauth.service.AuthenticationService;
import org.xdi.oxauth.service.ClientService;
import org.xdi.oxauth.service.ErrorHandlerService;
import org.xdi.oxauth.service.RequestParameterService;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.util.StringHelper;

/**
 * Authenticator component
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version August 9, 2017
 */
@RequestScoped
@Named
public class Authenticator {
    
    public static final String INVALID_SESSION_MESSAGE = "login.errorSessionInvalidMessage";
    public static final String AUTHENTICATION_ERROR_MESSAGE = "login.failedToAuthenticate";

    private static final String AUTH_EXTERNAL_ATTRIBUTES = "auth_external_attributes";

	@Inject
    private Logger log;

    @Inject
    private Identity identity;

    @Inject
    private Credentials credentials;

    @Inject
    private ClientService clientService;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private AuthenticationService authenticationService;

    @Inject
    private ExternalAuthenticationService externalAuthenticationService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private FacesContext facesContext;

    @Inject
    private FacesMessages facesMessages;

    @Inject
    private ExternalContext externalContext;

    @Inject
    private FacesService facesService;

    @Inject
    private LanguageBean languageBean;

    @Inject
    private RequestParameterService requestParameterService;

    @Inject
    private ErrorHandlerService errorHandlerService;

    private String authAcr;

    private Integer authStep;

    /**
     * Tries to authenticate an user, returns <code>true</code> if the
     * authentication succeed
     *
     * @return Returns <code>true</code> if the authentication succeed
     */
    public boolean authenticate() {
        String result = authenticateImpl(true, false);
        if (Constants.RESULT_SUCCESS.equals(result)) {
            return true;
        } else if (Constants.RESULT_FAILURE.equals(result)) {
            authenticationFailed();
        } else if (Constants.RESULT_NO_PERMISSIONS.equals(result)) {
            handlePermissionsError();
        } else if (Constants.RESULT_EXPIRED.equals(result)) {
            handleSessionInvalid();
        } else if (Constants.RESULT_AUTHENTICATION_FAILED.equals(result)) {
            // Do nothing to keep compatibility with older versions
            if (facesMessages.getMessages().size() == 0) {
                addMessage(FacesMessage.SEVERITY_ERROR, "login.failedToAuthenticate");
            }
        }
            
        return false;
    }

    public String authenticateWithOutcome() {
        String result = authenticateImpl(true, false);
        if (Constants.RESULT_SUCCESS.equals(result)) {
        } else if (Constants.RESULT_FAILURE.equals(result)) {
            authenticationFailed();
        } else if (Constants.RESULT_NO_PERMISSIONS.equals(result)) {
            handlePermissionsError();
        } else if (Constants.RESULT_EXPIRED.equals(result)) {
            handleSessionInvalid();
        } else if (Constants.RESULT_AUTHENTICATION_FAILED.equals(result)) {
            // Do nothing to keep compatibility with older versions
            if (facesMessages.getMessages().size() == 0) {
                addMessage(FacesMessage.SEVERITY_ERROR, "login.failedToAuthenticate");
            }
        }

        return result;
    }

    public boolean authenticateWebService(boolean skipPassword) {
        String result = authenticateImpl(false, skipPassword);
        return Constants.RESULT_SUCCESS.equals(result);
    }

    public boolean authenticateWebService() {
        String result = authenticateImpl(false, false);
        return Constants.RESULT_SUCCESS.equals(result);
    }

    public String authenticateImpl(boolean interactive, boolean skipPassword) {
        String result = Constants.RESULT_FAILURE;
        try {
            log.trace("Authenticating ... (interactive: " + interactive + ", skipPassword: " + skipPassword
                    + ", credentials.username: " + credentials.getUsername() + ")");
            if (StringHelper.isNotEmpty(credentials.getUsername())
                    && (skipPassword || StringHelper.isNotEmpty(credentials.getPassword()))
                    && credentials.getUsername().startsWith("@!")) {
                boolean authenticated = clientAuthentication(credentials, interactive, skipPassword);
                if (authenticated) {
                    result = Constants.RESULT_SUCCESS;
                }
            } else {
                if (interactive) {
                    result = userAuthenticationInteractive();
                } else {
                    boolean authenticated = userAuthenticationService();
                    if (authenticated) {
                        result = Constants.RESULT_SUCCESS;
                    }
                }
            }
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }

        if (Constants.RESULT_SUCCESS.equals(result)) {
            log.trace("Authentication successfully for '{}'", credentials.getUsername());
            return result;
        }

        log.info("Authentication failed for '{}'", credentials.getUsername());
        return result;
    }

    public boolean clientAuthentication(Credentials credentials, boolean interactive, boolean skipPassword) {
        boolean isServiceUsesExternalAuthenticator = !interactive
                && externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.SERVICE);
        if (isServiceUsesExternalAuthenticator) {
            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService
                    .determineCustomScriptConfiguration(AuthenticationScriptUsageType.SERVICE, 1, this.authAcr);

            if (customScriptConfiguration == null) {
                log.error("Failed to get CustomScriptConfiguration. acr: '{}'", this.authAcr);
            } else {
                this.authAcr = customScriptConfiguration.getCustomScript().getName();

                boolean result = externalAuthenticationService.executeExternalAuthenticate(customScriptConfiguration,
                        null, 1);
                log.info("Authentication result for user '{}', result: '{}'", credentials.getUsername(), result);

                if (result) {
                    Client client = authenticationService.configureSessionClient();
                    showClientAuthenticationLog(client);
                    return true;
                }
            }
        }

        boolean loggedIn = skipPassword;
        if (!loggedIn) {
            loggedIn = clientService.authenticate(credentials.getUsername(), credentials.getPassword());
        }
        if (loggedIn) {
            Client client = authenticationService.configureSessionClient();
            showClientAuthenticationLog(client);
            return true;
        }

        return false;
    }

    private void showClientAuthenticationLog(Client client) {
        StringBuilder sb = new StringBuilder("Authentication success for Client");
        if (StringHelper.toBoolean(appConfiguration.getLogClientIdOnClientAuthentication(), false) ||
                StringHelper.toBoolean(appConfiguration.getLogClientNameOnClientAuthentication(), false)) {
            sb.append(":");
            if (appConfiguration.getLogClientIdOnClientAuthentication()) {
                sb.append(" ").append("'").append(client.getClientId()).append("'");
            }
            if (appConfiguration.getLogClientNameOnClientAuthentication()) {
                sb.append(" ").append("('").append(client.getClientName()).append("')");
            }
        }
        log.info(sb.toString());
    }

    private String userAuthenticationInteractive() {
        SessionId sessionId = sessionIdService.getSessionId();
        Map<String, String> sessionIdAttributes = sessionIdService.getSessionAttributes(sessionId);
        if (sessionIdAttributes == null) {
            log.error("Failed to get session attributes");
            return Constants.RESULT_EXPIRED;
        }

        // Set current state into identity to allow use in login form and
        // authentication scripts
        identity.setSessionId(sessionId);

        initCustomAuthenticatorVariables(sessionIdAttributes);
        boolean useExternalAuthenticator = externalAuthenticationService
                .isEnabled(AuthenticationScriptUsageType.INTERACTIVE);
        if (useExternalAuthenticator && !StringHelper.isEmpty(this.authAcr)) {
            initCustomAuthenticatorVariables(sessionIdAttributes);
            if ((this.authStep == null) || StringHelper.isEmpty(this.authAcr)) {
                log.error("Failed to determine authentication mode");
                return Constants.RESULT_EXPIRED;
            }

            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService
                    .getCustomScriptConfiguration(AuthenticationScriptUsageType.INTERACTIVE, this.authAcr);
            if (customScriptConfiguration == null) {
                log.error("Failed to get CustomScriptConfiguration for acr: '{}', auth_step: '{}'", this.authAcr,
                        this.authStep);
                return Constants.RESULT_FAILURE;
            }

            // Check if all previous steps had passed
            boolean passedPreviousSteps = isPassedPreviousAuthSteps(sessionIdAttributes, this.authStep);
            if (!passedPreviousSteps) {
                log.error("There are authentication steps not marked as passed. acr: '{}', auth_step: '{}'",
                        this.authAcr, this.authStep);
                return Constants.RESULT_FAILURE;
            }

            // Restore identity working parameters from session
            setIdentityWorkingParameters(sessionIdAttributes);

            boolean result = externalAuthenticationService.executeExternalAuthenticate(customScriptConfiguration,
                    externalContext.getRequestParameterValuesMap(), this.authStep);
            log.debug("Authentication result for user '{}'. auth_step: '{}', result: '{}', credentials: '{}'",
                    credentials.getUsername(), this.authStep, result, System.identityHashCode(credentials));

            int overridenNextStep = -1;

            int apiVersion = externalAuthenticationService.executeExternalGetApiVersion(customScriptConfiguration);
            if (apiVersion > 1) {
                log.trace("According to API version script supports steps overriding");
                overridenNextStep = externalAuthenticationService.getNextStep(customScriptConfiguration,
                        externalContext.getRequestParameterValuesMap(), this.authStep);
                log.debug("Get next step from script: '{}'", apiVersion);
            }

            if (!result && (overridenNextStep == -1)) {
                return Constants.RESULT_AUTHENTICATION_FAILED;
            }

            boolean overrideCurrentStep = false;
            if (overridenNextStep > -1) {
                overrideCurrentStep = true;
                // Reload session id
                sessionId = sessionIdService.getSessionId();

                // Reset to specified step
                sessionIdService.resetToStep(sessionId, overridenNextStep);

                this.authStep = overridenNextStep;
                log.info("Authentication reset to step : '{}'", this.authStep);
            }

            // Update parameters map to allow access it from count
            // authentication steps method
            updateExtraParameters(customScriptConfiguration, this.authStep + 1, sessionIdAttributes);

            // Determine count authentication methods
            int countAuthenticationSteps = externalAuthenticationService
                    .executeExternalGetCountAuthenticationSteps(customScriptConfiguration);

            // Reload from LDAP to make sure that we are updating latest session
            // attributes
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

                String redirectTo = externalAuthenticationService
                        .executeExternalGetPageForStep(customScriptConfiguration, nextStep);
                if (StringHelper.isEmpty(redirectTo) || redirectTo == null) {
                    return Constants.RESULT_FAILURE;
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
                        return Constants.RESULT_EXPIRED;
                    }
                }

                log.trace("Redirect to page: '{}'", redirectTo);
    			facesService.redirectWithExternal(redirectTo, null);

    			return Constants.RESULT_SUCCESS;
            }

            if (this.authStep == countAuthenticationSteps) {
                SessionId eventSessionId = authenticationService.configureSessionUser(sessionId,
                        sessionIdAttributes);

                authenticationService.quietLogin(credentials.getUsername());

                // Redirect to authorization workflow
                log.debug("Sending event to trigger user redirection: '{}'", credentials.getUsername());
                authenticationService.onSuccessfulLogin(eventSessionId);

                log.info("Authentication success for User: '{}'", credentials.getUsername());
                return Constants.RESULT_SUCCESS;
            }
        } else {
            if (StringHelper.isNotEmpty(credentials.getUsername())) {
                boolean authenticated = authenticationService.authenticate(credentials.getUsername(),
                        credentials.getPassword());
                if (authenticated) {
                    SessionId eventSessionId = authenticationService.configureSessionUser(sessionId,
                            sessionIdAttributes);

                    // Redirect to authorization workflow
                    log.debug("Sending event to trigger user redirection: '{}'", credentials.getUsername());
                    authenticationService.onSuccessfulLogin(eventSessionId);
                }

                log.info("Authentication success for User: '{}'", credentials.getUsername());
                return Constants.RESULT_SUCCESS;
            }
        }

        return Constants.RESULT_FAILURE;
    }

    protected void handleSessionInvalid() {
        errorHandlerService.handleError(INVALID_SESSION_MESSAGE, AuthorizeErrorResponseType.AUTHENTICATION_SESSION_INVALID, "Create authorization request to start new authentication session.");
    }

    protected void handleScriptError() {
        handleScriptError(AUTHENTICATION_ERROR_MESSAGE);
    }

    protected void handleScriptError(String facesMessageId) {
        errorHandlerService.handleError(facesMessageId, AuthorizeErrorResponseType.INVALID_AUTHENTICATION_METHOD, "Contact administrator to fix specific ACR method issue.");
    }

    protected void handlePermissionsError() {
        errorHandlerService.handleError("login.youDontHavePermission", AuthorizeErrorResponseType.ACCESS_DENIED, "Contact administrator to grant access to resource.");
    }

    private boolean updateSession(SessionId sessionId, Map<String, String> sessionIdAttributes) {
        sessionId.setSessionAttributes(sessionIdAttributes);
        boolean updateResult = sessionIdService.updateSessionId(sessionId, true, true, true);
        if (!updateResult) {
            log.debug("Failed to update session entry: '{}'", sessionId.getId());
            return false;
        }

        return true;
    }

    private boolean userAuthenticationService() {
        if (externalAuthenticationService.isEnabled(AuthenticationScriptUsageType.SERVICE)) {
            CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService
                    .determineCustomScriptConfiguration(AuthenticationScriptUsageType.SERVICE, 1, this.authAcr);

            if (customScriptConfiguration == null) {
                log.error("Failed to get CustomScriptConfiguration. auth_step: '{}', acr: '{}'", this.authStep,
                        this.authAcr);
            } else {
                this.authAcr = customScriptConfiguration.getName();

                boolean result = externalAuthenticationService.executeExternalAuthenticate(customScriptConfiguration,
                        null, 1);
                log.info("Authentication result for '{}'. auth_step: '{}', result: '{}'", credentials.getUsername(),
                        this.authStep, result);

                if (result) {
                    authenticationService.configureEventUser();

                    log.info("Authentication success for User: '{}'", credentials.getUsername());
                    return true;
                }
                log.info("Authentication failed for User: '{}'", credentials.getUsername());
            }
        }

        if (StringHelper.isNotEmpty(credentials.getUsername())) {
            boolean authenticated = authenticationService.authenticate(credentials.getUsername(),
                    credentials.getPassword());
            if (authenticated) {
                authenticationService.configureEventUser();

                log.info("Authentication success for User: '{}'", credentials.getUsername());
                return true;
            }
            log.info("Authentication failed for User: '{}'", credentials.getUsername());
        }

        return false;
    }

    private void updateExtraParameters(CustomScriptConfiguration customScriptConfiguration, final int step,
                                       Map<String, String> sessionIdAttributes) {
        List<String> extraParameters = externalAuthenticationService
                .executeExternalGetExtraParametersForStep(customScriptConfiguration, step);

    	// Load extra parameters set
        Set<String> authExternalAttributes = getExternalScriptExtraParameters(sessionIdAttributes);
        
        if (extraParameters != null) {
            for (String extraParameter : extraParameters) {
                if (authenticationService.isParameterExists(extraParameter)) {
                	// Store parameter name
                	authExternalAttributes.add(extraParameter);

                	String extraParameterValue = requestParameterService.getParameterValue(extraParameter);
                    sessionIdAttributes.put(extraParameter, extraParameterValue);
                }
            }
        }

        // Store identity working parameters in session
        setExternalScriptExtraParameters(sessionIdAttributes, authExternalAttributes);
    }

	private Set<String> getExternalScriptExtraParameters(Map<String, String> sessionIdAttributes) {
		String authExternalAttributesString = sessionIdAttributes.get(AUTH_EXTERNAL_ATTRIBUTES);
        Set<String> authExternalAttributes = new HashSet<String>();
        try {
			List<String> list = Util.jsonArrayStringAsList(authExternalAttributesString);
			authExternalAttributes = new HashSet<String>(list);
		} catch (JSONException ex) {
			log.error("Failed to convert list of auth_external_attributes to list");
		}

        return authExternalAttributes;
	}

	private void setExternalScriptExtraParameters(Map<String, String> sessionIdAttributes, Set<String> authExternalAttributes) {
		String authExternalAttributesString = Util.listToJsonArray(authExternalAttributes).toString();

        sessionIdAttributes.put(AUTH_EXTERNAL_ATTRIBUTES, authExternalAttributesString);
	}

	private void clearExternalScriptExtraParameters(Map<String, String> sessionIdAttributes) {
        Set<String> authExternalAttributes = getExternalScriptExtraParameters(sessionIdAttributes);

        for (String authExternalAttribute : authExternalAttributes) {
    		sessionIdAttributes.remove(authExternalAttribute);
        }

        sessionIdAttributes.remove(AUTH_EXTERNAL_ATTRIBUTES);
	}

	private void setIdentityWorkingParameters(Map<String, String> sessionIdAttributes) {
        Set<String> authExternalAttributes = getExternalScriptExtraParameters(sessionIdAttributes);

        HashMap<String, Object> workingParameters = identity.getWorkingParameters();
        for (String authExternalAttribute : authExternalAttributes) {
        	if (sessionIdAttributes.containsKey(authExternalAttribute)) {
        		String authExternalAttributeValue = sessionIdAttributes.get(authExternalAttribute);
        		workingParameters.put(authExternalAttribute, authExternalAttributeValue);
        	}
		}
	}

    public String prepareAuthenticationForStep() {
        String result = prepareAuthenticationForStepImpl();

        if (Constants.RESULT_SUCCESS.equals(result)) {
        } else if (Constants.RESULT_FAILURE.equals(result)) {
            handleScriptError();
        } else if (Constants.RESULT_NO_PERMISSIONS.equals(result)) {
            handlePermissionsError();
        } else if (Constants.RESULT_EXPIRED.equals(result)) {
            handleSessionInvalid();
        }

        return result;
    }

    private String prepareAuthenticationForStepImpl() {
        SessionId sessionId = sessionIdService.getSessionId();
        Map<String, String> sessionIdAttributes = sessionIdService.getSessionAttributes(sessionId);
        if (sessionIdAttributes == null) {
            log.error("Failed to get attributes from session");
            return Constants.RESULT_EXPIRED;
        }

        // Set current state into identity to allow use in login form and
        // authentication scripts
        identity.setSessionId(sessionId);

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

        CustomScriptConfiguration customScriptConfiguration = externalAuthenticationService
                .getCustomScriptConfiguration(AuthenticationScriptUsageType.INTERACTIVE, this.authAcr);
        if (customScriptConfiguration == null) {
            log.error("Failed to get CustomScriptConfiguration. auth_step: '{}', acr: '{}'", this.authStep,
                    this.authAcr);
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
                String redirectTo = externalAuthenticationService
                        .executeExternalGetPageForStep(customScriptConfiguration, this.authStep);

                if (StringHelper.isEmpty(redirectTo)) {
                    redirectTo = "/login.xhtml";
                }

                CustomScriptConfiguration determinedCustomScriptConfiguration = externalAuthenticationService
                        .getCustomScriptConfiguration(AuthenticationScriptUsageType.INTERACTIVE, determinedauthAcr);
                if (determinedCustomScriptConfiguration == null) {
                    log.error("Failed to get determined CustomScriptConfiguration. auth_step: '{}', acr: '{}'",
                            this.authStep, this.authAcr);
                    return Constants.RESULT_FAILURE;
                }

                log.debug("Redirect to page: '{}'. Force to use acr: '{}'", redirectTo, determinedauthAcr);

                determinedauthAcr = determinedCustomScriptConfiguration.getName();
                String determinedAuthLevel = Integer.toString(determinedCustomScriptConfiguration.getLevel());

                sessionIdAttributes.put("acr", determinedauthAcr);
                sessionIdAttributes.put("auth_level", determinedAuthLevel);
                sessionIdAttributes.put("auth_step", Integer.toString(1));
                
                // Remove old session parameters from session
                clearExternalScriptExtraParameters(sessionIdAttributes);

                if (sessionId != null) {
                    boolean updateResult = updateSession(sessionId, sessionIdAttributes);
                    if (!updateResult) {
                        return Constants.RESULT_EXPIRED;
                    }
                }

    			facesService.redirectWithExternal(redirectTo, null);

                return Constants.RESULT_SUCCESS;
            }
        }

        // Check if all previous steps had passed
        boolean passedPreviousSteps = isPassedPreviousAuthSteps(sessionIdAttributes, this.authStep);
        if (!passedPreviousSteps) {
            log.error("There are authentication steps not marked as passed. acr: '{}', auth_step: '{}'", this.authAcr,
                    this.authStep);
            return Constants.RESULT_FAILURE;
        }

        // Restore identity working parameters from session
        setIdentityWorkingParameters(sessionIdAttributes);

        Boolean result = externalAuthenticationService.executeExternalPrepareForStep(customScriptConfiguration,
                externalContext.getRequestParameterValuesMap(), this.authStep);
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

        log.trace("authenticateBySessionId, sessionId = '{}', session = '{}', state= '{}'", p_sessionId,
                sessionId, sessionId.getState());
        // IMPORTANT : authenticate by session id only if state of session is authenticated!
        if (SessionIdState.AUTHENTICATED == sessionId.getState()) {
            final User user = authenticationService.getUserOrRemoveSession(sessionId);
            if (user != null) {
                try {
                    authenticationService.quietLogin(user.getUserId());

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
        addMessage(FacesMessage.SEVERITY_ERROR, "login.errorMessage");
        handleScriptError(null);
        return false;
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
        authenticationService.configureSessionClient(client);
    }

    public void addMessage(Severity severity, String summary) {
        String msg = languageBean.getMessage(summary);
        FacesMessage message = new FacesMessage(severity, msg, null);
        facesContext.addMessage(null, message);
    }

    public String getMaskMobilenumber(String mobile_number){
    	final String s = mobile_number.replaceAll("\\D", "");

        final int start = 0;
        final int end = s.length() - 4;
        final String overlay = StringUtils.repeat("*", end - start);

        return StringUtils.overlay(s, overlay, start, end);
    }
}