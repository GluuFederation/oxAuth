/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.revoke;

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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

/**
 * Provides interface for token revocation REST web services.
 * <p>
 * The oxAuth authorization server's revocation policy acts as follows:
 * The revocation of a particular token cause the revocation of related
 * tokens and the underlying authorization grant.  If the particular
 * token is a refresh token, then the authorization server will also
 * invalidate all access tokens based on the same authorization grant.
 * If the token passed to the request is an access token, the server will
 * revoke the respective refresh token as well.
 *
 * @author Javier Rojas Blum
 * @version January 16, 2019
 */
@Schema(defaultValue = "/", description = "Token Revocation Endpoint provides a mechanism to revoke both types of tokens: access_token and refresh_token")
public interface RevokeRestWebService {

    @POST
    @Path("/revoke")
    @Produces({MediaType.APPLICATION_JSON})
    @Operation(
    		description = "To revoke an Access Token or a Refresh Token, the RP (Client) sends a Token Revocation Request to the Token Revocation Endpoint",
    		summary = "To revoke an Access Token or a Refresh Token, the RP (Client) sends a Token Revocation Request to the Token Revocation Endpoint",
    		responses =  {
    	    		@ApiResponse(description = "Reponse object containing the revoke access details.", content = @Content(schema = @Schema(implementation = Response.class), mediaType="JSON"))
    	    }
    )
    
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "The authorization server responds with HTTP status code 200 if the " +
                    "token has been revoked successfully or if the client submitted an invalid token."),
            @ApiResponse(responseCode = "200", description = "unsupported_token_type\n" +
                    "The authorization server does not support the revocation of the presented token type.")
    })
    Response requestAccessToken(
            @FormParam("token")
            @Parameter(description = "The token that the client wants to get revoked.", required = true)
                    String token,
            @FormParam("token_type_hint")
            @Parameter(description = "A hint about the type of the token submitted for revocation.", required = false)
                    String tokenTypeHint,
            @Context HttpServletRequest request,
            @Context HttpServletResponse response,
            @Context SecurityContext sec);
}
