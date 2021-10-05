package org.gluu.oxauth.service.external.context;

import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.oxauth.model.common.AuthorizationGrant;
import org.gluu.oxauth.model.registration.Client;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

/**
 * @author Yuriy Zabrovarnyy
 */
public class RevokeTokenContext extends ExternalScriptContext {

    private final Client client;
    private final AuthorizationGrant grant;
    private final Response.ResponseBuilder responseBuilder;
    private CustomScriptConfiguration script;

    public RevokeTokenContext(HttpServletRequest httpRequest, Client client, AuthorizationGrant grant, Response.ResponseBuilder responseBuilder) {
        super(httpRequest);
        this.client = client;
        this.grant = grant;
        this.responseBuilder = responseBuilder;
    }

    public Client getClient() {
        return client;
    }

    public AuthorizationGrant getGrant() {
        return grant;
    }

    public Response.ResponseBuilder getResponseBuilder() {
        return responseBuilder;
    }

    public CustomScriptConfiguration getScript() {
        return script;
    }

    public void setScript(CustomScriptConfiguration script) {
        this.script = script;
    }

    @Override
    public String toString() {
        return "RevokeTokenContext{" +
                "clientId=" + (client != null ? client.getClientId() : "") +
                ", script=" + (script != null ? script.getName() : "") +
                "} " + super.toString();
    }
}
