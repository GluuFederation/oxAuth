/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.authorize.ws.rs;

import com.wordnik.swagger.annotations.Api;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceErrorResponseType;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceParamsValidator;
import org.xdi.oxauth.model.authorize.AuthorizeDeviceResponseParam;
import org.xdi.oxauth.model.authorize.ScopeChecker;
import org.xdi.oxauth.model.common.AuthorizationGrant;
import org.xdi.oxauth.model.common.AuthorizationGrantList;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.registration.Client;
import org.xdi.oxauth.model.util.UserCodeGenerator;
import org.xdi.oxauth.service.ClientService;
import org.xdi.util.StringHelper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.util.*;

/**
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
@Name("requestDeviceAuthorizationRestWebService")
@Api(value = "/oxauth/authorize_device", description = "Device Authorization Endpoint")
public class AuthorizeDeviceRestWebServiceImpl implements AuthorizeDeviceRestWebService {

    @Logger
    private Log log;
    @In
    private ClientService clientService;
    @In
    private ScopeChecker scopeChecker;
    @In
    private AuthorizationGrantList authorizationGrantList;
    @In
    private ErrorResponseFactory errorResponseFactory;
    @In
    private ConfigurationFactory configurationFactory;

    @Override
    public Response requestDeviceAuthorizationPost(String clientId, String scope,
                                                   HttpServletRequest httpRequest,
                                                   HttpServletResponse httpResponse,
                                                   SecurityContext securityContext) {
        log.debug("Attempting to request device authorization: clientId = {0}, scope = {1}, isSecure = {2}",
                clientId, scope, securityContext.isSecure());

        Response.ResponseBuilder builder = Response.ok();

        try {
            if (!AuthorizeDeviceParamsValidator.validateParams(clientId, scope)) {
                builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                builder.entity(errorResponseFactory.getErrorAsJson(
                        AuthorizeDeviceErrorResponseType.INVALID_REQUEST, null));
            } else {
                Client client = clientService.getClient(clientId);
                List<String> scopesRequested = Arrays.asList(scope.split(" "));
                List<String> scopes = new ArrayList<String>();
                if (StringHelper.isNotEmpty(scope)) {
                    Set<String> grantedScopes = scopeChecker.checkScopesPolicy(client, scope);
                    scopes.addAll(grantedScopes);
                }

                if (!scopes.containsAll(scopesRequested)) {
                    builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()); // 400
                    builder.entity(errorResponseFactory.getErrorAsJson(
                            AuthorizeDeviceErrorResponseType.INVALID_SCOPE, null));
                } else {
                    String verificationUri = configurationFactory.getConfiguration().getDeviceVerificationUri();
                    int expiresIn = configurationFactory.getConfiguration().getDeviceVerificationCodeLifetime();
                    int interval = configurationFactory.getConfiguration().getDevicePollInterval();
                    String deviceCode = UUID.randomUUID().toString();
                    String userCode = UserCodeGenerator.generateUserCode();

                    AuthorizationGrant authorizationGrant = authorizationGrantList.createDeviceAuthorizationGrant(
                            client, deviceCode, userCode, expiresIn);
                    authorizationGrant.setScopes(scopes);
                    authorizationGrant.save();

                    JSONObject response = new JSONObject();
                    response.put(AuthorizeDeviceResponseParam.DEVICE_CODE, deviceCode);
                    response.put(AuthorizeDeviceResponseParam.USER_CODE, userCode);
                    response.put(AuthorizeDeviceResponseParam.VERIFICATION_URI, verificationUri);
                    response.put(AuthorizeDeviceResponseParam.EXPIRES_IN, expiresIn);
                    response.put(AuthorizeDeviceResponseParam.INTERVAL, interval);

                    CacheControl cacheControl = new CacheControl();
                    cacheControl.setPrivate(true);
                    cacheControl.setNoTransform(false);
                    cacheControl.setNoStore(true);
                    builder.cacheControl(cacheControl);
                    builder.header("Pragma", "no-cache");
                    builder.entity(response.toString(4).replace("\\/", "/"));
                }
            }
        } catch (JSONException e) {
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()); // 500
            log.error(e.getMessage(), e);
        }

        return builder.build();
    }
}
