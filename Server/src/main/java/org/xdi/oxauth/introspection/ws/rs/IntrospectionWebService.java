/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.introspection.ws.rs;

import com.wordnik.swagger.annotations.Api;
import org.apache.commons.lang.StringUtils;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.xdi.oxauth.model.authorize.AuthorizeErrorResponseType;
import org.xdi.oxauth.model.common.*;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.uma.UmaScopeType;
import org.xdi.oxauth.service.token.TokenService;
import org.xdi.oxauth.util.ServerUtil;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 17/09/2013
 */
@Name("introspectionWS")
@Path("/introspection")
@Api(value= "/introspection", description = "The Introspection Endpoint is an OAuth 2 Endpoint that responds to " +
        "   HTTP GET and HTTP POST requests from token holders.  The endpoint " +
        "   takes a single parameter representing the token (and optionally " +
        "   further authentication) and returns a JSON document representing the meta information surrounding the token.")
public class IntrospectionWebService {

    @Logger
    private Log log;
    @In
    private TokenService tokenService;
    @In
    private ErrorResponseFactory errorResponseFactory;
    @In
    private AuthorizationGrantList authorizationGrantList;
    @In
    private AppConfiguration appConfiguration;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectGet(@HeaderParam("Authorization") String p_authorization,
                                  @QueryParam("token") String p_token,
                                  @QueryParam("token_type_hint") String tokenTypeHint
    ) {
        return introspect(p_authorization, p_token, tokenTypeHint);
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspectPost(@HeaderParam("Authorization") String p_authorization,
                                   @FormParam("token") String p_token,
                                   @FormParam("token_type_hint") String tokenTypeHint
    ) {
        return introspect(p_authorization, p_token, tokenTypeHint);
    }

    private Response introspect(String p_authorization, String p_token, String tokenTypeHint) {
        try {
            log.trace("Introspect token, authorization: {}, token to introsppect: {}, tokenTypeHint:", p_authorization, p_token, tokenTypeHint);
            if (StringUtils.isNotBlank(p_authorization) && StringUtils.isNotBlank(p_token)) {
                final AuthorizationGrant authorizationGrant = tokenService.getAuthorizationGrant(p_authorization);
                if (authorizationGrant != null) {
                    final AbstractToken authorizationAccessToken = authorizationGrant.getAccessToken(tokenService.getTokenFromAuthorizationParameter(p_authorization));
                    boolean isPat = authorizationGrant.getScopesAsString().contains(UmaScopeType.PROTECTION.getValue()); // #432
                    if (authorizationAccessToken != null && authorizationAccessToken.isValid() && isPat) {
                        final IntrospectionResponse response = new IntrospectionResponse(false);

                        final AuthorizationGrant grantOfIntrospectionToken = authorizationGrantList.getAuthorizationGrantByAccessToken(p_token);
                        if (grantOfIntrospectionToken != null) {
                            final AbstractToken tokenToIntrospect = grantOfIntrospectionToken.getAccessToken(p_token);

                            response.setActive(tokenToIntrospect.isValid());
                            response.setExpiresAt(tokenToIntrospect.getExpirationDate());
                            response.setIssuedAt(tokenToIntrospect.getCreationDate());
                            response.setAcrValues(tokenToIntrospect.getAuthMode());
                            response.setScopes(grantOfIntrospectionToken.getScopes() != null ? grantOfIntrospectionToken.getScopes() : new ArrayList<String>()); // #433
                            response.setClientId(grantOfIntrospectionToken.getClientId());
                            response.setUsername(grantOfIntrospectionToken.getUserId());
                            response.setIssuer(appConfiguration.getIssuer());
                            response.setAudience(grantOfIntrospectionToken.getClientId());

                            if (tokenToIntrospect instanceof AccessToken) {
                                AccessToken accessToken = (AccessToken) tokenToIntrospect;
                                response.setTokenType(accessToken.getTokenType() != null ? accessToken.getTokenType().getName() : TokenType.BEARER.getName());
                            }
                        } else {
                            log.error("Failed to find grant for access_token: " + p_token);
                        }
                        return Response.status(Response.Status.OK).entity(ServerUtil.asJson(response)).build();
                    } else {
                        log.error("Access token is not valid. Valid: " + (authorizationAccessToken != null && authorizationAccessToken.isValid()) + ", isPat:" + isPat);
                    }
                } else {
                    log.error("Authorization grant is null.");
                }

                return Response.status(Response.Status.BAD_REQUEST).entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.ACCESS_DENIED)).build();
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        return Response.status(Response.Status.BAD_REQUEST).entity(errorResponseFactory.getErrorAsJson(AuthorizeErrorResponseType.INVALID_REQUEST)).build();
    }
}
