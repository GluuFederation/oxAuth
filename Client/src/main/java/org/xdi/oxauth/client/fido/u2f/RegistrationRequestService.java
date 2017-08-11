/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client.fido.u2f;

import org.xdi.oxauth.model.fido.u2f.protocol.RegisterRequestMessage;
import org.xdi.oxauth.model.fido.u2f.protocol.RegisterStatus;

import javax.ws.rs.*;

/**
 * Еhe endpoint allows to start and finish U2F registration process
 *
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
public interface RegistrationRequestService {

    @GET
    @Produces({"application/json"})
    public RegisterRequestMessage startRegistration(@QueryParam("username") String userName, @QueryParam("application") String appId, @QueryParam("session_id") String sessionId);

    @POST
    @Produces({"application/json"})
    public RegisterStatus finishRegistration(@FormParam("username") String userName, @FormParam("tokenResponse") String registerResponseString);

}