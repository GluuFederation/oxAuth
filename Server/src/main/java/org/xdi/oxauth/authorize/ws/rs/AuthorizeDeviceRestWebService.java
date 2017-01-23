/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.authorize.ws.rs;

import com.wordnik.swagger.annotations.*;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceRequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

/**
 * The device flow is suitable for clients executing on devices that do
 * not have an easy data-entry method and where the client is incapable
 * of receiving incoming requests from the authorization server
 * (incapable of acting as an HTTP server).
 * <p/>
 * Instead of interacting with the end-user's user-agent, the client
 * instructs the end-user to use another computer or device and connect
 * to the authorization server to approve the access request.  Since the
 * client cannot receive incoming requests, it polls the authorization
 * server repeatedly until the end-user completes the approval process.
 *
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
@Path("/oxauth")
@Api(value = "/oxauth", description = "The authorization server's endpoint capable of issuing verification codes, user codes, and verification URLs for OAuth 2.0 Device Flow.")
public interface AuthorizeDeviceRestWebService {

    @POST
    @Path("/authorize_device")
    @Produces({MediaType.APPLICATION_JSON})
    @ApiOperation(
            value = "Performs device authorization.",
            notes = "The device flow is suitable for clients executing on devices that do not have an easy data-entry method and where the client is incapable of receiving incoming requests from the authorization server (incapable of acting as an HTTP server).",
            response = Response.class,
            responseContainer = "JSON"
    )
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "invalid_request\n" +
                    "The request is missing a required parameter, includes an unsupported parameter value or is otherwise malformed."),
            @ApiResponse(code = 400, message = "invalid_scope\n" +
                    "The requested scope is invalid, unknown, or malformed.")
    })
    Response requestDeviceAuthorizationPost(
            @FormParam(AuthorizeDeviceRequestParam.CLIENT_ID)
            @ApiParam(value = "OAuth 2.0 Client Identifier valid at the Authorization Server. ", required = true)
                    String clientId,
            @FormParam(AuthorizeDeviceRequestParam.SCOPE)
            @ApiParam(value = "The scope of the access request.", required = true)
                    String scope,
            @Context HttpServletRequest httpRequest,
            @Context HttpServletResponse httpResponse,
            @Context SecurityContext securityContext
    );
}
