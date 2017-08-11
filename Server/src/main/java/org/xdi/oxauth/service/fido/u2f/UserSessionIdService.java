/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.service.fido.u2f;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.log.Log;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.common.SessionIdState;
import org.xdi.oxauth.model.fido.u2f.DeviceRegistrationResult;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.ws.rs.fido.u2f.U2fAuthenticationWS;
import org.xdi.util.StringHelper;

import java.util.Map;

/**
 * Configure user session to confirm user {@link U2fAuthenticationWS} authentication
 *
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
@Scope(ScopeType.STATELESS)
@Name("userSessionIdService")
@AutoCreate
public class UserSessionIdService {

    @Logger
    private Log log;

    @In
    private SessionIdService sessionIdService;

    public void updateUserSessionIdOnFinishRequest(String sessionId, String userInum, DeviceRegistrationResult deviceRegistrationResult, boolean enroll, boolean oneStep) {
        SessionId ldapSessionId = getLdapSessionId(sessionId);
        if (ldapSessionId == null) {
            return;
        }

        Map<String, String> sessionAttributes = ldapSessionId.getSessionAttributes();
        if (DeviceRegistrationResult.Status.APPROVED == deviceRegistrationResult.getStatus()) {
            sessionAttributes.put("session_custom_state", "approved");
        } else {
            sessionAttributes.put("session_custom_state", "declined");
        }
        sessionAttributes.put("oxpush2_u2f_device_id", deviceRegistrationResult.getDeviceRegistration().getId());
        sessionAttributes.put("oxpush2_u2f_device_user_inum", userInum);
        sessionAttributes.put("oxpush2_u2f_device_enroll", Boolean.toString(enroll));
        sessionAttributes.put("oxpush2_u2f_device_one_step", Boolean.toString(oneStep));

        sessionIdService.updateSessionId(ldapSessionId, true);
    }

    public void updateUserSessionIdOnError(String sessionId) {
        SessionId ldapSessionId = getLdapSessionId(sessionId);
        if (ldapSessionId == null) {
            return;
        }

        Map<String, String> sessionAttributes = ldapSessionId.getSessionAttributes();
        sessionAttributes.put("session_custom_state", "declined");

        sessionIdService.updateSessionId(ldapSessionId, true);
    }

    private SessionId getLdapSessionId(String sessionId) {
        if (StringHelper.isEmpty(sessionId)) {
            return null;
        }

        SessionId ldapSessionId = sessionIdService.getSessionId(sessionId);
        if (ldapSessionId == null) {
            log.warn("Failed to load session id '{0}'", sessionId);
            return null;
        }

        if (SessionIdState.UNAUTHENTICATED != ldapSessionId.getState()) {
            log.warn("Unexpected session, id: '{0}', state: '{1}'", sessionId, ldapSessionId.getState());
            return null;
        }

        return ldapSessionId;
    }

}
