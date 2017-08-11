/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2015, Gluu
 */

package org.xdi.oxauth.ws.rs.fido.u2f;

import com.wordnik.swagger.annotations.Api;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.xdi.model.custom.script.conf.CustomScriptConfiguration;
import org.xdi.oxauth.model.common.SessionId;
import org.xdi.oxauth.model.common.User;
import org.xdi.oxauth.model.config.Constants;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.fido.u2f.*;
import org.xdi.oxauth.model.fido.u2f.exception.BadInputException;
import org.xdi.oxauth.model.fido.u2f.exception.RegistrationNotAllowed;
import org.xdi.oxauth.model.fido.u2f.protocol.RegisterRequestMessage;
import org.xdi.oxauth.model.fido.u2f.protocol.RegisterResponse;
import org.xdi.oxauth.model.fido.u2f.protocol.RegisterStatus;
import org.xdi.oxauth.service.SessionIdService;
import org.xdi.oxauth.service.UserService;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;
import org.xdi.oxauth.service.fido.u2f.DeviceRegistrationService;
import org.xdi.oxauth.service.fido.u2f.RegistrationService;
import org.xdi.oxauth.service.fido.u2f.UserSessionIdService;
import org.xdi.oxauth.service.fido.u2f.ValidationService;
import org.xdi.oxauth.util.ServerUtil;
import org.xdi.util.StringHelper;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.List;

/**
 * The endpoint allows to start and finish U2F registration process
 *
 * @author Yuriy Movchan
 * @version August 11, 2017
 */
@Path("/fido/u2f/registration")
@Api(value = "/fido/u2f/registration", description = "The endpoint at which the U2F device start registration process.")
@Name("u2fRegistrationRestWebService")
public class U2fRegistrationWS {

    @Logger
    private Log log;

    @In
    private UserService userService;

    @In
    private ErrorResponseFactory errorResponseFactory;

    @In
    private RegistrationService u2fRegistrationService;

    @In
    private DeviceRegistrationService deviceRegistrationService;

    @In
    private SessionIdService sessionIdService;

    @In
    private UserSessionIdService userSessionIdService;

    @In
    private ValidationService u2fValidationService;

    @GET
    @Produces({"application/json"})
    public Response startRegistration(@QueryParam("username") String userName, @QueryParam("application") String appId, @QueryParam("session_id") String sessionId, @QueryParam("enrollment_code") String enrollmentCode) {
        // Parameter username is deprecated. We uses it only to determine is it's one or two step workflow
        try {
            log.debug("Startig registration with username '{0}' for appId '{1}'. session_id '{2}', enrollment_code '{3}'", userName, appId, sessionId, enrollmentCode);

            String userInum = null;

            boolean sessionBasedEnrollment = false;
            boolean twoStep = StringHelper.isNotEmpty(userName);
            if (twoStep) {
                boolean removeEnrollment = false;
                if (StringHelper.isNotEmpty(sessionId)) {
                    boolean valid = u2fValidationService.isValidSessionId(userName, sessionId);
                    if (!valid) {
                        throw new BadInputException(String.format("session_id '%s' is invalid", sessionId));
                    }
                    sessionBasedEnrollment = true;
                } else if (StringHelper.isNotEmpty(enrollmentCode)) {
                    boolean valid = u2fValidationService.isValidEnrollmentCode(userName, enrollmentCode);
                    if (!valid) {
                        throw new BadInputException(String.format("enrollment_code '%s' is invalid", enrollmentCode));
                    }
                    removeEnrollment = true;
                } else {
                    throw new BadInputException(String.format("session_id or enrollment_code is mandatory"));
                }

                User user = userService.getUser(userName);
                userInum = userService.getUserInum(user);
                if (StringHelper.isEmpty(userInum)) {
                    throw new BadInputException(String.format("Failed to find user '%s' in LDAP", userName));
                }

                if (removeEnrollment) {
                    // We allow to use enrollment code only one time
                    user.setAttribute(U2fConstants.U2F_ENROLLMENT_CODE_ATTRIBUTE, (String) null);
                    userService.updateUser(user);
                }
            }

            if (sessionBasedEnrollment) {
                List<DeviceRegistration> deviceRegistrations = deviceRegistrationService.findUserDeviceRegistrations(userInum, appId);
                if (deviceRegistrations.size() > 0 && !isCurrentAuthenticationLevelCorrespondsToU2fLevel(sessionId)) {
                    throw new RegistrationNotAllowed(String.format("It's not possible to start registration with user_name and session_id because user '%s' has already enrolled device", userName));
                }
            }

            RegisterRequestMessage registerRequestMessage = u2fRegistrationService.builRegisterRequestMessage(appId, userInum);
            u2fRegistrationService.storeRegisterRequestMessage(registerRequestMessage, userInum, sessionId);

            // Convert manually to avoid possible conflict between resteasy providers, e.g. jettison, jackson
            final String entity = ServerUtil.asJson(registerRequestMessage);

            return Response.status(Response.Status.OK).entity(entity).cacheControl(ServerUtil.cacheControl(true)).build();
        } catch (Exception ex) {
            log.error("Exception happened", ex);
            if (ex instanceof WebApplicationException) {
                throw (WebApplicationException) ex;
            }

            if (ex instanceof RegistrationNotAllowed) {
                throw new WebApplicationException(Response.status(Response.Status.NOT_ACCEPTABLE)
                        .entity(errorResponseFactory.getErrorResponse(U2fErrorResponseType.REGISTRATION_NOT_ALLOWED)).build());
            }

            throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(errorResponseFactory.getJsonErrorResponse(U2fErrorResponseType.SERVER_ERROR)).build());
        }
    }

    @POST
    @Produces({"application/json"})
    public Response finishRegistration(@FormParam("username") String userName, @FormParam("tokenResponse") String registerResponseString) {
        String sessionId = null;
        try {
            log.debug("Finishing registration for username '{0}' with response '{1}'", userName, registerResponseString);

            RegisterResponse registerResponse = ServerUtil.jsonMapperWithWrapRoot().readValue(registerResponseString, RegisterResponse.class);

            String requestId = registerResponse.getRequestId();
            RegisterRequestMessageLdap registerRequestMessageLdap = u2fRegistrationService.getRegisterRequestMessageByRequestId(requestId);
            if (registerRequestMessageLdap == null) {
                throw new WebApplicationException(Response.status(Response.Status.FORBIDDEN)
                        .entity(errorResponseFactory.getJsonErrorResponse(U2fErrorResponseType.SESSION_EXPIRED)).build());
            }
            u2fRegistrationService.removeRegisterRequestMessage(registerRequestMessageLdap);

            String foundUserInum = registerRequestMessageLdap.getUserInum();

            RegisterRequestMessage registerRequestMessage = registerRequestMessageLdap.getRegisterRequestMessage();
            DeviceRegistrationResult deviceRegistrationResult = u2fRegistrationService.finishRegistration(registerRequestMessage, registerResponse, foundUserInum);

            // If sessionId is not empty update session
            sessionId = registerRequestMessageLdap.getSessionId();
            if (StringHelper.isNotEmpty(sessionId)) {
                log.debug("There is session id. Setting session id attributes");

                boolean oneStep = StringHelper.isEmpty(foundUserInum);
                userSessionIdService.updateUserSessionIdOnFinishRequest(sessionId, foundUserInum, deviceRegistrationResult, true, oneStep);
            }

            RegisterStatus registerStatus = new RegisterStatus(Constants.RESULT_SUCCESS, requestId);

            // Convert manually to avoid possible conflict between resteasy providers, e.g. jettison, jackson
            final String entity = ServerUtil.asJson(registerStatus);

            return Response.status(Response.Status.OK).entity(entity).cacheControl(ServerUtil.cacheControl(true)).build();
        } catch (Exception ex) {
            log.error("Exception happened", ex);

            try {
                // If sessionId is not empty update session
                if (StringHelper.isNotEmpty(sessionId)) {
                    log.debug("There is session id. Setting session id status to 'declined'");
                    userSessionIdService.updateUserSessionIdOnError(sessionId);
                }
            } catch (Exception ex2) {
                log.error("Failed to update session id status", ex2);
            }

            if (ex instanceof WebApplicationException) {
                throw (WebApplicationException) ex;
            }

            if (ex instanceof BadInputException) {
                throw new WebApplicationException(Response.status(Response.Status.FORBIDDEN)
                        .entity(errorResponseFactory.getErrorResponse(U2fErrorResponseType.INVALID_REQUEST)).build());
            }

            throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(errorResponseFactory.getJsonErrorResponse(U2fErrorResponseType.SERVER_ERROR)).build());
        }
    }

    private boolean isCurrentAuthenticationLevelCorrespondsToU2fLevel(String session) {
        SessionId sessionId = sessionIdService.getSessionId(session);
        if (sessionId == null)
            return false;

        String acrValuesStr = sessionIdService.getAcr(sessionId);
        if (acrValuesStr == null)
            return false;

        ExternalAuthenticationService service = ExternalAuthenticationService.instance();
        CustomScriptConfiguration u2fScriptConfiguration = service.getCustomScriptConfigurationByName("u2f");
        if (u2fScriptConfiguration == null)
            return false;

        String[] acrValuesArray = acrValuesStr.split(" ");
        for (String acrValue : acrValuesArray) {
            CustomScriptConfiguration currentScriptConfiguration = service.getCustomScriptConfigurationByName(acrValue);
            if (currentScriptConfiguration == null)
                continue;

            if (currentScriptConfiguration.getLevel() >= u2fScriptConfiguration.getLevel())
                return true;
        }

        return false;
    }

}
