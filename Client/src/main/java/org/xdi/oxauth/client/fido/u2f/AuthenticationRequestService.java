/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.client.fido.u2f;

import org.xdi.oxauth.model.fido.u2f.protocol.AuthenticateRequestMessage;
import org.xdi.oxauth.model.fido.u2f.protocol.AuthenticateStatus;

import javax.ws.rs.*;

/**
 * The endpoint allows to start and finish U2F authentication process
 * 
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
public interface AuthenticationRequestService {

	@GET
	@Produces({ "application/json" })
	public AuthenticateRequestMessage startAuthentication(@QueryParam("username") String userName, @QueryParam("keyhandle") String keyHandle, @QueryParam("application") String appId, @QueryParam("session_id") String sessionId);

	@POST
	@Produces({ "application/json" })
	public AuthenticateStatus finishAuthentication(@FormParam("username") String userName, @FormParam("tokenResponse") String authenticateResponseString);

}