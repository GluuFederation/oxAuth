/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */

package org.gluu.oxauth.authorize.ws.rs;

import org.gluu.jsf2.service.FacesService;
import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.oxauth.i18n.LanguageBean;
import org.gluu.oxauth.model.authorize.AuthorizeRequestParam;
import org.gluu.oxauth.model.authorize.ScopeChecker;
import org.gluu.oxauth.model.config.Constants;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.service.AuthorizeService;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.SessionIdService;
import org.gluu.oxauth.service.common.UserService;
import org.gluu.oxauth.service.external.ExternalConsentGatheringService;
import org.gluu.oxauth.service.external.context.ConsentGatheringContext;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

import javax.enterprise.context.RequestScoped;
import javax.faces.application.FacesMessage;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * @author Yuriy Movchan Date: 10/30/2017
 */
@RequestScoped
@Named(value = "consentGatherer")
public class ConsentGathererService {

    @Inject
    private Logger log;

    @Inject
    private ExternalConsentGatheringService external;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private FacesContext facesContext;

    @Inject
    private ExternalContext externalContext;

    @Inject
    private FacesService facesService;

    @Inject
    private LanguageBean languageBean;

    @Inject
    private ConsentGatheringSessionService sessionService;

    @Inject
    private UserService userService;

    @Inject
    private AuthorizeService authorizeService;

    @Inject
    private ClientService clientService;
    
    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private ScopeChecker scopeChecker;

    private final Map<String, String> pageAttributes = new HashMap<String, String>();
    private ConsentGatheringContext context;
    
    public boolean configure(String userDn, String clientId, String state) {
        final HttpServletRequest httpRequest = (HttpServletRequest) externalContext.getRequest();
        final HttpServletResponse httpResponse = (HttpServletResponse) externalContext.getResponse();

        final SessionId session = sessionService.getConsentSession(httpRequest, httpResponse, userDn, true);

        CustomScriptConfiguration script = determineConsentScript(clientId);
        if (script == null) {
            log.error("Failed to determine consent-gathering script");
            return false;
        }

        sessionService.configure(session, script.getName(), clientId, state);

        this.context = new ConsentGatheringContext(script.getConfigurationAttributes(), httpRequest, httpResponse, session,
        		pageAttributes, sessionService, userService, facesService, appConfiguration);
        log.debug("Configuring consent-gathering script '{}'", script.getName());

        int step = sessionService.getStep(session);
        String redirectTo = external.getPageForStep(script, step, context);
        if (StringHelper.isEmpty(redirectTo)) {
            log.error("Failed to determine page for consent-gathering script");
        	return false;
        }

        context.persist();

        log.trace("Redirecting to page: '{}'", redirectTo);
		facesService.redirectWithExternal(redirectTo, null);

		return true;
    }

    private CustomScriptConfiguration determineConsentScript(String clientId) {
        if (appConfiguration.getConsentGatheringScriptBackwardCompatibility()) {
            // in 4.1 and earlier we returned default consent script
            return external.getDefaultExternalCustomScript();
        }

        final List<String> consentGatheringScripts = clientService.getClient(clientId).getAttributes().getConsentGatheringScripts();
        final List<CustomScriptConfiguration> scripts = external.getCustomScriptConfigurationsByDns(consentGatheringScripts);
        if (!scripts.isEmpty()) {
            final CustomScriptConfiguration script = Collections.max(scripts, Comparator.comparingInt(CustomScriptConfiguration::getLevel)); // flow supports single script, thus taking the one with higher level
            log.debug("Determined consent gathering script `%s`", script.getName());
            return script;
        }

        log.debug("There no consent gathering script configured for client `%s`. Therefore taking default consent script.", clientId);
        return external.getDefaultExternalCustomScript();
    }

    public boolean authorize() {
        try {
            final HttpServletRequest httpRequest = (HttpServletRequest) externalContext.getRequest();
            final HttpServletResponse httpResponse = (HttpServletResponse) externalContext.getResponse();

            final SessionId session = sessionService.getConsentSession(httpRequest, httpResponse, null, false);
            if (session == null) {
                log.error("Failed to restore claim-gathering session state");
            	errorPage("consent.gather.invalid.session");
                return false;
            }

            CustomScriptConfiguration script = getScript(session);
            if (script == null) {
                log.error("Failed to find script '{}' in session:", sessionService.getScriptName(session));
            	errorPage("consent.gather.failed");
                return false;
            }

            int step = sessionService.getStep(session);
            if (!sessionService.isPassedPreviousSteps(session, step)) {
                log.error("There are consent-gathering steps not marked as passed. scriptName: '{}', step: '{}'", script.getName(), step);
            	errorPage("consent.gather.invalid.step");
                return false;
            }

            this.context = new ConsentGatheringContext(script.getConfigurationAttributes(), httpRequest, httpResponse, session,
                    pageAttributes, sessionService, userService, facesService, appConfiguration);
            boolean authorizeResult = external.authorize(script, step, context);
            log.debug("Consent-gathering result for script '{}', step: '{}', gatheredResult: '{}'", script.getName(), step, authorizeResult);

            int overridenNextStep = external.getNextStep(script, step, context);
            if (!authorizeResult && overridenNextStep == -1) {
            	SessionId connectSession = sessionService.getConnectSession(httpRequest);
            	authorizeService.permissionDenied(connectSession);
                return false;
            }

            if (overridenNextStep != -1) {
                sessionService.resetToStep(session, overridenNextStep, step);
                step = overridenNextStep;
            }

            int stepsCount = external.getStepsCount(script, context);
            if (step < stepsCount || overridenNextStep != -1) {
                int nextStep;
                if (overridenNextStep != -1) {
                    nextStep = overridenNextStep;
                } else {
                    nextStep = step + 1;
                    sessionService.markStep(session, step, true);
                }

                sessionService.setStep(nextStep, session);

                String redirectTo = external.getPageForStep(script, nextStep, context);
                context.persist();

                log.trace("Redirecting to page: '{}'", redirectTo);
    			facesService.redirectWithExternal(redirectTo, null);

    			return true;
            }

            if (step == stepsCount) {
                context.persist();
                onSuccess(httpRequest, session, context);
                return true;
            }
        } catch (Exception e) {
            log.error("Exception during gather() method call.", e);
        }

        log.error("Failed to perform gather() method successfully.");
    	errorPage("consent.gather.failed");
        return false;
    }

    private void onSuccess(HttpServletRequest httpRequest, SessionId session, ConsentGatheringContext context) {
    	sessionService.setAuthenticatedSessionState(httpRequest, context.getHttpResponse(), session);
    	
    	SessionId connectSessionId = sessionService.getConnectSession(httpRequest);
    	
    	authorizeService.permissionGranted(httpRequest, connectSessionId);
    }

    public String prepareForStep() {
        try {
            final HttpServletRequest httpRequest = (HttpServletRequest) externalContext.getRequest();
            final HttpServletResponse httpResponse = (HttpServletResponse) externalContext.getResponse();

            final SessionId session = sessionService.getConsentSession(httpRequest, httpResponse, null, false);
            if (session == null || session.getSessionAttributes().isEmpty()) {
            	log.error("Failed to restore claim-gathering session state");
                return result(Constants.RESULT_EXPIRED);
            }

            CustomScriptConfiguration script = getScript(session);
            if (script == null) {
                log.error("Failed to find script '{}' in session:", sessionService.getScriptName(session));
                return result(Constants.RESULT_FAILURE);
            }

            int step = sessionService.getStep(session);
            if (step < 1) {
                log.error("Invalid step: {}", step);
                return result(Constants.RESULT_INVALID_STEP);
            }

            if (!sessionService.isPassedPreviousSteps(session, step)) {
                log.error("There are consent-gathering steps not marked as passed. scriptName: '{}', step: '{}'", script.getName(), step);
                return result(Constants.RESULT_FAILURE);
            }

            this.context = new ConsentGatheringContext(script.getConfigurationAttributes(), httpRequest, httpResponse, session,
            		pageAttributes, sessionService, userService, facesService, appConfiguration);
            boolean result = external.prepareForStep(script, step, context);
            log.debug("Consent-gathering prepare for step result for script '{}', step: '{}', gatheredResult: '{}'", script.getName(), step, result);
            if (result) {
                context.persist();
                return result(Constants.RESULT_SUCCESS);
            }
        } catch (Exception ex) {
            log.error("Failed to prepareForStep()", ex);
        }

        return result(Constants.RESULT_FAILURE);
    }

    private void errorPage(String errorKey) {
        addMessage(FacesMessage.SEVERITY_ERROR, errorKey);
        facesService.redirect("/error.xhtml");
    }

    public String result(String resultCode) {
        if (Constants.RESULT_FAILURE.equals(resultCode)) {
            addMessage(FacesMessage.SEVERITY_ERROR, "consent.gather.failed");
        } else if (Constants.RESULT_INVALID_STEP.equals(resultCode)) {
            addMessage(FacesMessage.SEVERITY_ERROR, "consent.gather.invalid.step");
        } else if (Constants.RESULT_EXPIRED.equals(resultCode)) {
            addMessage(FacesMessage.SEVERITY_ERROR, "consent.gather.invalid.session");
        }
        return resultCode;
    }

    public void addMessage(FacesMessage.Severity severity, String summary) {
        String msg = languageBean.getMessage(summary);
        FacesMessage message = new FacesMessage(severity, msg, null);
        facesContext.addMessage(null, message);
    }

    public Map<String, String> getPageAttributes() {
        return pageAttributes;
    }

    protected CustomScriptConfiguration getScript(final SessionId session) {
		String scriptName = sessionService.getScriptName(session);
		CustomScriptConfiguration script = external.getCustomScriptConfigurationByName(scriptName);

		return script;
	}

	public boolean isConsentGathered() {
        final HttpServletRequest httpRequest = (HttpServletRequest) externalContext.getRequest();
        return sessionService.isSessionStateAuthenticated(httpRequest);
	}

	public ConsentGatheringContext getContext() {
		return context;
	}

    public List<org.oxauth.persistence.model.Scope> getScopes() {
    	if (context == null) {
    		return Collections.emptyList();
    	}

    	SessionId authenticatedSessionId = sessionIdService.getSessionId();
        // Fix the list of scopes in the authorization page. oxAuth #739
        Set<String> grantedScopes = scopeChecker.checkScopesPolicy(context.getClient(), authenticatedSessionId.getSessionAttributes().get(AuthorizeRequestParam.SCOPE));
        String allowedScope = org.gluu.oxauth.model.util.StringUtils.implode(grantedScopes, " ");

        return authorizeService.getScopes(allowedScope);
    }

}
