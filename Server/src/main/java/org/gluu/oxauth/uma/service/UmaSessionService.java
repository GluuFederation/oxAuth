/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */

package org.gluu.oxauth.uma.service;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.common.User;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.model.uma.persistence.UmaPermission;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.CookieService;
import org.gluu.oxauth.service.SessionIdService;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.List;

/**
 * @author yuriyz
 * @version December 8, 2018
 */
@ApplicationScoped
public class UmaSessionService {

    @Inject
    private Logger log;
    @Inject
    private SessionIdService sessionIdService;
    @Inject
    private ClientService clientService;
    @Inject
    private CookieService cookieService;

    public SessionId getConnectSession(HttpServletRequest httpRequest) {
        String cookieId = cookieService.getSessionIdFromCookie(httpRequest);
        log.trace("Cookie - session_id: " + cookieId);
        if (StringUtils.isNotBlank(cookieId)) {
            return sessionIdService.getSessionId(cookieId);
        }
        return null;
    }

    public SessionId getSession(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String cookieId = cookieService.getUmaSessionIdFromCookie(httpRequest);
        log.trace("Cookie - uma_session_id: " + cookieId);

        if (StringUtils.isNotBlank(cookieId)) {
            SessionId sessionId = sessionIdService.getSessionId(cookieId);
            if (sessionId != null) {
                log.trace("Loaded uma_session_id from cookie, session: " + sessionId);
                return sessionId;
            } else {
                log.error("Failed to load uma_session_id from cookie: " + cookieId);
            }
        } else {
            log.error("uma_session_id cookie is not set.");
        }

        log.trace("Generating new uma_session_id ...");
        SessionId session = sessionIdService.generateAuthenticatedSessionId(httpRequest, "", new HashMap<String, String>() {{
            put("uma", "true");
        }});

        cookieService.createSessionIdCookie(session, httpRequest, httpResponse, true);
        log.trace("uma_session_id cookie created.");
        return session;
    }

    public boolean persist(SessionId session) {
        try {

            if (sessionIdService.updateSessionId(session, true, true, true)) {
                log.trace("Session persisted successfully. Session: " + session);
                return true;
            }
        } catch (Exception e) {
            log.error("Failed to persist session, id: " + session.getId(), e);
        }
        return false;
    }

    public int getStep(SessionId session) {
        String stepString = session.getSessionAttributes().get("step");
        int step = Util.parseIntSilently(stepString);
        if (step == -1) {
            step = 1;
            setStep(step, session);
        }
        return step;
    }

    public void setStep(int step, SessionId session) {
        session.getSessionAttributes().put("step", Integer.toString(step));
    }

    public void configure(SessionId session, String scriptName, Boolean reset, List<UmaPermission> permissions,
                          String clientId, String claimRedirectUri, String state) {
        setStep(1, session);
        setState(session, state);
        setClaimsRedirectUri(session, claimRedirectUri);
        setTicket(session, permissions.get(0).getTicket());
        setScriptName(session, scriptName);

        String pct = permissions.get(0).getAttributes().get("pct");

        if (StringUtils.isBlank(pct)) {
            log.error("PCT code is null or blank in permission object.");
            throw new RuntimeException("PCT code is null or blank in permission object.");
        }

        setPct(session, pct);
        setClientId(session, clientId);
        persist(session);
    }

    public boolean isStepPassed(SessionId session, Integer step) {
        return Boolean.parseBoolean(session.getSessionAttributes().get(String.format("uma_step_passed_%d", step)));
    }

    public boolean isPassedPreviousSteps(SessionId session, Integer step) {
        for (int i = 1; i < step; i++) {
            if (!isStepPassed(session, i)) {
                return false;
            }
        }
        return true;
    }

    public void markStep(SessionId session, Integer step, boolean value) {
        String key = String.format("uma_step_passed_%d", step);
        if (value) {
            session.getSessionAttributes().put(key, Boolean.TRUE.toString());
        } else {
            session.getSessionAttributes().remove(key);
        }
    }

    public String getScriptName(SessionId session) {
        return session.getSessionAttributes().get("gather_script_name");
    }

    public void setScriptName(SessionId session, String scriptName) {
        session.getSessionAttributes().put("gather_script_name", scriptName);
    }

    public String getPct(SessionId session) {
        return session.getSessionAttributes().get("pct");
    }

    public void setPct(SessionId session, String pct) {
        session.getSessionAttributes().put("pct", pct);
    }

    public String getClientId(SessionId session) {
        return session.getSessionAttributes().get("client_id");
    }

    public void setClientId(SessionId session, String clientId) {
        session.getSessionAttributes().put("client_id", clientId);
    }

    public String getClaimsRedirectUri(SessionId session) {
        return session.getSessionAttributes().get("claims_redirect_uri");
    }

    public void setClaimsRedirectUri(SessionId session, String claimsRedirectUri) {
        session.getSessionAttributes().put("claims_redirect_uri", claimsRedirectUri);
    }

    public String getState(SessionId session) {
        return session.getSessionAttributes().get("state");
    }

    public void setState(SessionId session, String state) {
        session.getSessionAttributes().put("state", state);
    }

    public String getTicket(SessionId session) {
        return session.getSessionAttributes().get("ticket");
    }

    public void setTicket(SessionId session, String ticket) {
        session.getSessionAttributes().put("ticket", ticket);
    }

    public void resetToStep(SessionId session, int overridenNextStep, int step) {
        for (int i = overridenNextStep; i <= step; i++) {
            markStep(session, i, false);
        }

        setStep(overridenNextStep, session);
    }

    public User getUser(HttpServletRequest httpRequest, String... returnAttributes) {
        return sessionIdService.getUser(getConnectSession(httpRequest));
    }

    public String getUserDn(HttpServletRequest httpRequest) {
        SessionId connectSession = getConnectSession(httpRequest);
        if (connectSession != null) {
            return connectSession.getUserDn();
        }

        log.trace("No logged in user.");
        return null;
    }

    public Client getClient(SessionId session) {
        String clientId = getClientId(session);
        if (StringUtils.isNotBlank(clientId)) {
            return clientService.getClient(clientId);
        }
        log.trace("client_id is not in session.");
        return null;
    }
}
