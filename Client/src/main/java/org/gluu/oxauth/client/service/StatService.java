package org.gluu.oxauth.client.service;

import com.fasterxml.jackson.databind.JsonNode;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

/**
 * @author Yuriy Zabrovarnyy
 */
public interface StatService {
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    JsonNode stat(@HeaderParam("Authorization") String authorization, @QueryParam("month") String month, @QueryParam("format") String format);

    @POST
    @Produces({MediaType.APPLICATION_JSON})
    JsonNode statPost(@HeaderParam("Authorization") String authorization, @FormParam("month") String month, @FormParam("format") String format);
}
