package org.gluu.oxauth.client;

import javax.ws.rs.core.Response;

import org.gluu.oxauth.model.session.EndSessionErrorResponseType;

/**
 * @author Yuriy Zabrovarnyy
 */
public class RevokeSessionResponse extends BaseResponseWithErrors<EndSessionErrorResponseType>{

    public RevokeSessionResponse() {
    }

    public RevokeSessionResponse(Response clientResponse) {
        super(clientResponse);
        injectDataFromJson();
    }

    @Override
    public EndSessionErrorResponseType fromString(String params) {
        return EndSessionErrorResponseType.fromString(params);
    }

    public void injectDataFromJson() {
        injectDataFromJson(entity);
    }
}
