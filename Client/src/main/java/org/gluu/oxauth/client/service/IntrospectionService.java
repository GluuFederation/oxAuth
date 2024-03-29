/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.client.service;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.gluu.oxauth.model.common.IntrospectionResponse;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Introspection service.
 *
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 17/09/2013
 */

public interface IntrospectionService {

    /**
     * Returns introspection response for specified token.
     *
     * @param p_authorization authorization token
     * @param p_token         token to introspect
     * @return introspection response
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    IntrospectionResponse introspectToken(@HeaderParam("Authorization") String p_authorization, @FormParam("token") String p_token);

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    String introspectTokenWithResponseAsJwt(@HeaderParam("Authorization") String p_authorization, @FormParam("token") String p_token, @FormParam("response_as_jwt") boolean responseAsJwt);

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    JsonNode introspect(@HeaderParam("Authorization") String p_authorization, @FormParam("token") String p_token);

}
