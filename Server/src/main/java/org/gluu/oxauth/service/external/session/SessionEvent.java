package org.gluu.oxauth.service.external.session;

import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.oxauth.model.session.SessionId;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Yuriy Zabrovarnyy
 */
public class SessionEvent {

    private final SessionEventType type;
    private final SessionId sessionId;
    private CustomScriptConfiguration scriptConfiguration;
    private HttpServletRequest httpRequest;
    private HttpServletResponse httpResponse;

    public SessionEvent(SessionEventType type, SessionId sessionId) {
        this.type = type;
        this.sessionId = sessionId;
    }

    public SessionEventType getType() {
        return type;
    }

    public SessionId getSessionId() {
        return sessionId;
    }

    public CustomScriptConfiguration getScriptConfiguration() {
        return scriptConfiguration;
    }

    public void setScriptConfiguration(CustomScriptConfiguration scriptConfiguration) {
        this.scriptConfiguration = scriptConfiguration;
    }

    public HttpServletRequest getHttpRequest() {
        return httpRequest;
    }

    public SessionEvent setHttpRequest(HttpServletRequest httpRequest) {
        this.httpRequest = httpRequest;
        return this;
    }

    public HttpServletResponse getHttpResponse() {
        return httpResponse;
    }

    public SessionEvent setHttpResponse(HttpServletResponse httpResponse) {
        this.httpResponse = httpResponse;
        return this;
    }

    @Override
    public String toString() {
        return "SessionEvent{" +
                "type=" + type +
                ", sessionId=" + sessionId.getId() +
                '}';
    }
}
