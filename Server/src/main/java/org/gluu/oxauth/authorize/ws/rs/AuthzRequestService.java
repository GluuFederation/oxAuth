package org.gluu.oxauth.authorize.ws.rs;

import org.gluu.oxauth.model.audit.Action;
import org.gluu.oxauth.model.audit.OAuth2AuditLog;
import org.gluu.oxauth.util.ServerUtil;

import javax.enterprise.context.RequestScoped;
import javax.inject.Named;
import javax.ws.rs.WebApplicationException;

/**
 * @author Yuriy Z
 */
@RequestScoped
@Named
public class AuthzRequestService {

    public static boolean canLogWebApplicationException(WebApplicationException e) {
        if (e == null || e.getResponse() == null) {
            return false;
        }
        final int status = e.getResponse().getStatus();
        return status != 302;
    }

    public void createOauth2AuditLog(AuthzRequest authzRequest) {
        createOauth2AuditLog(authzRequest, Action.USER_AUTHORIZATION);
    }

    public void createOauth2AuditLog(AuthzRequest authzRequest, Action action) {
        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(authzRequest.getHttpRequest()), action);
        oAuth2AuditLog.setClientId(authzRequest.getClientId());
        oAuth2AuditLog.setScope(authzRequest.getScope());

        authzRequest.setAuditLog(oAuth2AuditLog);
    }
}
