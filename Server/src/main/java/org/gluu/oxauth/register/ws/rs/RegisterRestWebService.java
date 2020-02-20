/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.register.ws.rs;


import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
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
 * Provides interface for register REST web services.
 *
 * @author Javier Rojas Blum
 * @author Yuriy Zabrovarnyy
 * @version 0.1, 01.11.2012
 */
@Schema(defaultValue = "/", description = "The Client Registration Endpoint is an OAuth 2.0 Protected Resource through which a new Client registration can be requested. The OpenID Provider MAY require an Initial Access Token that is provisioned out-of-band (in a manner that is out of scope for this specification) to restrict registration requests to only authorized Clients or developers.")
public interface RegisterRestWebService {

    /**
     * In order for an OpenID Connect client to utilize OpenID services for a user, the client needs to register with
     * the OpenID Provider to acquire a client ID and shared secret.
     *
     * @param requestParams   request parameters
     * @param authorization   authorization
     * @param httpRequest     http request object
     * @param securityContext An injectable interface that provides access to security related information.
     * @return response
     */
    @POST
    @Path("/register")
    @Produces({MediaType.APPLICATION_JSON})
    @Operation(
    		description = "Registers new client dynamically.",
            summary = "Registers new client dynamically.",
    		responses =  {
    	    		@ApiResponse(description = "Reponse object containing the new client registration request status.", content = @Content(schema = @Schema(implementation = Response.class), mediaType="JSON"))
    	    }
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "400", description = "invalid_request\n" +
                    "The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad Request) status code."),
            @ApiResponse(responseCode = "400", description = "invalid_redirect_uri\n" +
                    "The value of one or more redirect_uris is invalid. "),
            @ApiResponse(responseCode = "400", description = "invalid_client_metadata\n" +
                    "The value of one of the Client Metadata fields is invalid and the server has rejected this request. Note that an Authorization Server MAY choose to substitute a valid value for any requested parameter of a Client's Metadata."),
            @ApiResponse(responseCode = "302", description = "access_denies\n" +
                    "The authorization server denied the request.")

    })
    Response requestRegister(
            @Parameter(description = "Request parameters as JSON object with data described by Connect Client Registration Specification. ", required = true)
            String requestParams,
            @HeaderParam("Authorization") String authorization,
            @Context HttpServletRequest httpRequest,
            @Context SecurityContext securityContext);

    /**
     * This operation updates the Client Metadata for a previously registered client.
     *
     * @param requestParams   request parameters
     * @param clientId        client id
     * @param authorization   Access Token that is used at the Client Configuration Endpoint
     * @param httpRequest     http request object
     * @param securityContext An injectable interface that provides access to security related information.
     * @return response
     */

    @PUT
    @Path("register")
    @Produces({MediaType.APPLICATION_JSON})
    @Operation(
    		description = "Updates client info.",
            summary = "Updates client info.",
    		responses =  {
    	    		@ApiResponse(description = "Reponse object containing the update client registration request status.", content = @Content(schema = @Schema(implementation = Response.class), mediaType="JSON"))
    	    }
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "400", description = "invalid_request\n" +
                    "The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad Request) status code."),
            @ApiResponse(responseCode = "400", description = "invalid_redirect_uri\n" +
                    "The value of one or more redirect_uris is invalid. "),
            @ApiResponse(responseCode = "400", description = "invalid_client_metadata\n" +
                    "The value of one of the Client Metadata fields is invalid and the server has rejected this request. Note that an Authorization Server MAY choose to substitute a valid value for any requested parameter of a Client's Metadata."),
            @ApiResponse(responseCode = "302", description = "access_denies\n" +
                    "The authorization server denied the request.")
    })
    Response requestClientUpdate(
            @Parameter(description = "Request parameters as JSON object with data described by Connect Client Registration Specification. ", required = true)
            String requestParams,
            @QueryParam("client_id")
            @Parameter(description = "Client ID that identifies client that must be updated by this request.", required = true)
            String clientId,
            @HeaderParam("Authorization") String authorization,
            @Context HttpServletRequest httpRequest,
            @Context SecurityContext securityContext);

    /**
     * This operation retrieves the Client Metadata for a previously registered client.
     *
     * @param clientId        Unique Client identifier.
     * @param securityContext An injectable interface that provides access to security related information.
     * @return response
     */
    @GET
    @Path("/register")
    @Produces({MediaType.APPLICATION_JSON})
    @Operation(
            description = "Reads client info.",
            summary = "Reads client info.",
    		responses =  {
    	    		@ApiResponse(description = "Reponse object containing the client registration meta data.", content = @Content(schema = @Schema(implementation = Response.class), mediaType="JSON"))
    	    }
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "400", description = "invalid_request\n" +
                    "The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad Request) status code."),
            @ApiResponse(responseCode = "400", description = "invalid_redirect_uri\n" +
                    "The value of one or more redirect_uris is invalid. "),
            @ApiResponse(responseCode = "400", description = "invalid_client_metadata\n" +
                    "The value of one of the Client Metadata fields is invalid and the server has rejected this request. Note that an Authorization Server MAY choose to substitute a valid value for any requested parameter of a Client's Metadata."),
            @ApiResponse(responseCode = "302", description = "access_denies\n" +
                    "The authorization server denied the request.")
    })
    Response requestClientRead(
            @QueryParam("client_id")
            @Parameter(description = "Client ID that identifies client.", required = true)
            String clientId,
            @HeaderParam("Authorization") String authorization,
            @Context HttpServletRequest httpRequest,
            @Context SecurityContext securityContext);

    /**
     * This operation removes the Client Metadata for a previously registered client.
     *
     * @param clientId        Unique Client identifier.
     * @param securityContext An injectable interface that provides access to security related information.
     * @return If a client has been successfully deprovisioned, the authorization
     * server responds with an HTTP 204 No Content message.
     * <p>
     * If the registration access token used to make this request is not
     * valid, the server responds with HTTP 401 Unauthorized.
     * <p>
     * If the client does not exist on this server, the server responds
     * with HTTP 401 Unauthorized.
     * <p>
     * If the client is not allowed to delete itself, the server
     * responds with HTTP 403 Forbidden.
     */
    @DELETE
    @Path("/register")
    @Produces({MediaType.APPLICATION_JSON})
    @Operation(
    		description = "Deletes client info.",
            summary = "Deletes client info.",
    		responses =  {
    	    		@ApiResponse(description = "Reponse object containing the delete client registration status.", content = @Content(schema = @Schema(implementation = Response.class), mediaType="JSON"))
    	    }
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "401", description = "invalid_token\n" +
                    "The registration access token used to make this request is not valid"),
            @ApiResponse(responseCode = "401", description = "invalid_client_id\n" +
                    "The client does not exist on this server "),
            @ApiResponse(responseCode = "403", description = "not_allowed\n" +
                    "The client is not allowed to delete itself")
    })
    Response delete(
            @QueryParam("client_id")
            @Parameter(description = "Client ID that identifies client.", required = true) String clientId,
            @HeaderParam("Authorization") String authorization,
            @Context HttpServletRequest httpRequest,
            @Context SecurityContext securityContext);
}