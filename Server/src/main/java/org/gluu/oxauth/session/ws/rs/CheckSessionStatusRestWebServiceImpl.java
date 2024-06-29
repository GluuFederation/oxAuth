/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.session.ws.rs;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.gluu.oxauth.model.session.SessionId;
import org.gluu.oxauth.service.CookieService;
import org.gluu.oxauth.service.SessionIdService;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.util.Date;

/**
 * @author Yuriy Movchan
 * @version August 9, 2017
 */
@Path("/")
public class CheckSessionStatusRestWebServiceImpl {

    @Inject
    private Logger log;

    @Inject
    private SessionIdService sessionIdService;

    @Inject
    private CookieService cookieService;

    @GET
    @Path("/session_status")
    @Produces({MediaType.APPLICATION_JSON})
    public Response requestCheckSessionStatus(@Context HttpServletRequest httpRequest, @Context HttpServletResponse httpResponse,
                                              @Context SecurityContext securityContext) throws IOException {
        String sessionIdCookie = cookieService.getSessionIdFromCookie(httpRequest);
        log.debug("Found session '{}' cookie: '{}'", CookieService.SESSION_ID_COOKIE_NAME, sessionIdCookie);

        CheckSessionResponse response = new CheckSessionResponse("unknown", "");

        SessionId sessionId = sessionIdService.getSessionId(sessionIdCookie);
        if (sessionId != null) {
            response.setState(sessionId.getState().getValue());
            response.setAuthTime(sessionId.getAuthenticationTime());

            String sessionCustomState = sessionId.getSessionAttributes().get(SessionIdService.SESSION_CUSTOM_STATE);
            if (StringHelper.isNotEmpty(sessionCustomState)) {
                response.setCustomState(sessionCustomState);
            }
        }

        String responseJson = ServerUtil.asJson(response);
        log.debug("Check session status response: '{}'", responseJson);

        return Response.ok().type(MediaType.APPLICATION_JSON).entity(responseJson).build();
    }

    class CheckSessionResponse {

        @JsonProperty(value = "state")
        String state;

        @JsonProperty(value = "custom_state")
        String customState;

        @JsonProperty(value = "auth_time")
        Date authTime;

        public CheckSessionResponse(String state, String stateExt) {
            this.state = state;
            this.customState = stateExt;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getCustomState() {
            return customState;
        }

        public void setCustomState(String customState) {
            this.customState = customState;
        }

        public Date getAuthTime() {
            return authTime;
        }

        public void setAuthTime(Date authTime) {
            this.authTime = authTime;
        }

    }

}
