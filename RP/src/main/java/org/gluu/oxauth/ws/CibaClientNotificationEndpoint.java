/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.ws;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

/**
 * It is used to process CIBA callbacks for ping and push modes.
 */
public interface CibaClientNotificationEndpoint {

    @POST
    @Path("/cb")
    @Produces({MediaType.APPLICATION_JSON})
    Response processCallback(
            @HeaderParam("Authorization") String authorization,
            String requestParams,
            @Context HttpServletRequest request,
            @Context SecurityContext securityContext);

}