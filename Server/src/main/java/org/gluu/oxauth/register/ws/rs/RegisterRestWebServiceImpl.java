/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.register.ws.rs;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.gluu.model.GluuAttribute;
import org.gluu.model.metric.MetricType;
import org.gluu.oxauth.audit.ApplicationAuditLogger;
import org.gluu.oxauth.ciba.CIBARegisterClientMetadataService;
import org.gluu.oxauth.ciba.CIBARegisterClientResponseService;
import org.gluu.oxauth.ciba.CIBARegisterParamsValidatorService;
import org.gluu.oxauth.client.RegisterRequest;
import org.gluu.oxauth.model.audit.Action;
import org.gluu.oxauth.model.audit.OAuth2AuditLog;
import org.gluu.oxauth.model.common.*;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.error.ErrorResponseFactory;
import org.gluu.oxauth.model.exception.InvalidJwtException;
import org.gluu.oxauth.model.json.JsonApplier;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.oxauth.model.register.RegisterErrorResponseType;
import org.gluu.oxauth.model.register.RegisterResponseParam;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.registration.RegisterParamsValidator;
import org.gluu.oxauth.model.token.HandleTokenFactory;
import org.gluu.oxauth.model.util.JwtUtil;
import org.gluu.oxauth.model.util.Pair;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.AttributeService;
import org.gluu.oxauth.service.ClientService;
import org.gluu.oxauth.service.MetricService;
import org.gluu.oxauth.service.ScopeService;
import org.gluu.oxauth.service.common.InumService;
import org.gluu.oxauth.service.external.ExternalDynamicClientRegistrationService;
import org.gluu.oxauth.service.token.TokenService;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.persist.model.base.CustomAttribute;
import org.gluu.util.StringHelper;
import org.gluu.util.security.StringEncrypter;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.oxauth.persistence.model.Scope;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.net.URI;
import java.util.*;

import static org.apache.commons.lang3.BooleanUtils.isTrue;
import static org.gluu.oxauth.model.register.RegisterRequestParam.*;
import static org.gluu.oxauth.model.register.RegisterResponseParam.*;
import static org.gluu.oxauth.model.util.StringUtils.implode;
import static org.gluu.oxauth.model.util.StringUtils.toList;

/**
 * Implementation for register REST web services.
 *
 * @author Javier Rojas Blum
 * @author Yuriy Zabrovarnyy
 * @author Yuriy Movchan
 * @version May 20, 2020
 */
@Path("/")
public class RegisterRestWebServiceImpl implements RegisterRestWebService {

    @Inject
    private Logger log;
    @Inject
    private ApplicationAuditLogger applicationAuditLogger;
    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Inject
    private ScopeService scopeService;

    @Inject
    private AttributeService attributeService;

    @Inject
    private InumService inumService;
    @Inject
    private ClientService clientService;
    @Inject
    private TokenService tokenService;

    @Inject
    private MetricService metricService;

    @Inject
    private ExternalDynamicClientRegistrationService externalDynamicClientRegistrationService;

    @Inject
    private RegisterParamsValidator registerParamsValidator;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private AbstractCryptoProvider cryptoProvider;

    @Inject
    private CIBARegisterParamsValidatorService cibaRegisterParamsValidatorService;

    @Inject
    private CIBARegisterClientMetadataService cibaRegisterClientMetadataService;

    @Inject
    private CIBARegisterClientResponseService cibaRegisterClientResponseService;

    @Inject
    private AuthorizationGrantList authorizationGrantList;

    @Override
    public Response requestRegister(String requestParams, HttpServletRequest httpRequest, SecurityContext securityContext) {
        com.codahale.metrics.Timer.Context timerContext = metricService.getTimer(MetricType.DYNAMIC_CLIENT_REGISTRATION_RATE).time();
        try {
            return registerClientImpl(requestParams, httpRequest, securityContext);
        } finally {
            timerContext.stop();
        }
    }

    private Response registerClientImpl(String requestParams, HttpServletRequest httpRequest, SecurityContext securityContext) {
        Response.ResponseBuilder builder = Response.status(Response.Status.CREATED);
        if (appConfiguration.getReturn200OnClientRegistration()) {
            builder = Response.ok();
        }

        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(httpRequest), Action.CLIENT_REGISTRATION);
        try {
            final JSONObject requestObject = new JSONObject(requestParams);
            final JSONObject softwareStatement = validateSoftwareStatement(httpRequest, requestObject);
            if (softwareStatement != null) {
                log.trace("Override request parameters by software_statement");
                for (String key : softwareStatement.keySet()) {
                    requestObject.putOpt(key, softwareStatement.get(key));
                }
            }

            final RegisterRequest r = RegisterRequest.fromJson(requestObject, appConfiguration.getLegacyDynamicRegistrationScopeParam());
            if (requestObject.has(SOFTWARE_STATEMENT.toString())) {
                r.setSoftwareStatement(requestObject.getString(SOFTWARE_STATEMENT.toString()));
            }

            log.info("Attempting to register client: applicationType = {}, clientName = {}, redirectUris = {}, isSecure = {}, sectorIdentifierUri = {}, defaultAcrValues = {}",
                    r.getApplicationType(), r.getClientName(), r.getRedirectUris(), securityContext.isSecure(), r.getSectorIdentifierUri(), r.getDefaultAcrValues());
            log.trace("Registration request = {}", requestParams);

            if (!appConfiguration.getDynamicRegistrationEnabled()) {
                log.info("Dynamic client registration is disabled.");
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.ACCESS_DENIED, "Dynamic client registration is disabled.");
            }

            if (!appConfiguration.getDynamicRegistrationPasswordGrantTypeEnabled()
                    && registerParamsValidator.checkIfThereIsPasswordGrantType(r.getGrantTypes())) {
                log.info("Password Grant Type is not allowed for Dynamic Client Registration.");
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.ACCESS_DENIED, "Password Grant Type is not allowed for Dynamic Client Registration.");
            }

            if (r.getSubjectType() == null) {
                SubjectType defaultSubjectType = SubjectType.fromString(appConfiguration.getDefaultSubjectType());
                if (defaultSubjectType != null) {
                    r.setSubjectType(defaultSubjectType);
                } else if (appConfiguration.getSubjectTypesSupported().contains(SubjectType.PUBLIC.toString())) {
                    r.setSubjectType(SubjectType.PUBLIC);
                } else if (appConfiguration.getSubjectTypesSupported().contains(SubjectType.PAIRWISE.toString())) {
                    r.setSubjectType(SubjectType.PAIRWISE);
                }
            }

            registerParamsValidator.validateAlgorithms(r); // Throws a WebApplicationException whether a validation doesn't pass

            if (r.getIdTokenSignedResponseAlg() == null) {
                r.setIdTokenSignedResponseAlg(SignatureAlgorithm.fromString(appConfiguration.getDefaultSignatureAlgorithm()));
            }
            if (r.getAccessTokenSigningAlg() == null) {
                r.setAccessTokenSigningAlg(SignatureAlgorithm.fromString(appConfiguration.getDefaultSignatureAlgorithm()));
            }

            if (r.getClaimsRedirectUris() != null && !r.getClaimsRedirectUris().isEmpty()) {
                if (!registerParamsValidator.validateRedirectUris(r.getGrantTypes(), r.getResponseTypes(),
                        r.getApplicationType(), r.getSubjectType(), r.getClaimsRedirectUris(), r.getSectorIdentifierUri())) {
                    log.debug("Value of one or more claims_redirect_uris is invalid, claims_redirect_uris: " + r.getClaimsRedirectUris());
                    throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLAIMS_REDIRECT_URI, "Value of one or more claims_redirect_uris is invalid");
                }
            }

            if (!Strings.isNullOrEmpty(r.getInitiateLoginUri())) {
                if (!registerParamsValidator.validateInitiateLoginUri(r.getInitiateLoginUri())) {
                    log.debug("The Initiate Login Uri is invalid. The initiate_login_uri must use the https schema: " + r.getInitiateLoginUri());
                    throw errorResponseFactory.createWebApplicationException(
                            Response.Status.BAD_REQUEST,
                            RegisterErrorResponseType.INVALID_CLIENT_METADATA,
                            "The Initiate Login Uri is invalid. The initiate_login_uri must use the https schema.");
                }
            }

            final Pair<Boolean, String> validateResult = registerParamsValidator.validateParamsClientRegister(
                    r.getApplicationType(), r.getSubjectType(),
                    r.getGrantTypes(), r.getResponseTypes(),
                    r.getRedirectUris());
            if (!validateResult.getFirst()) {
                log.trace("Client parameters are invalid, returns invalid_request error. Reason: " + validateResult.getSecond());
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLIENT_METADATA, validateResult.getSecond());
            }

            if (!registerParamsValidator.validateRedirectUris(
                    r.getGrantTypes(), r.getResponseTypes(),
                    r.getApplicationType(), r.getSubjectType(),
                    r.getRedirectUris(), r.getSectorIdentifierUri())) {
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_REDIRECT_URI, "Failed to validate redirect uris.");
            }

            if (!cibaRegisterParamsValidatorService.validateParams(
                    r.getBackchannelTokenDeliveryMode(),
                    r.getBackchannelClientNotificationEndpoint(),
                    r.getBackchannelAuthenticationRequestSigningAlg(),
                    r.getBackchannelUserCodeParameter(),
                    r.getGrantTypes(),
                    r.getSubjectType(),
                    r.getSectorIdentifierUri(),
                    r.getJwks(),
                    r.getJwksUri()
            )) { // CIBA
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLIENT_METADATA,
                        "Invalid Client Metadata registering to use CIBA (Client Initiated Backchannel Authentication).");
            }


            registerParamsValidator.validateLogoutUri(r.getFrontChannelLogoutUris(), r.getRedirectUris(), errorResponseFactory);
            registerParamsValidator.validateLogoutUri(r.getBackchannelLogoutUris(), r.getRedirectUris(), errorResponseFactory);

            String clientsBaseDN = staticConfiguration.getBaseDn().getClients();

            String inum = inumService.generateClientInum();
            String generatedClientSecret = UUID.randomUUID().toString();

            final Client client = new Client();
            client.setDn("inum=" + inum + "," + clientsBaseDN);
            client.setClientId(inum);
            client.setDeletable(true);
            client.setClientSecret(clientService.encryptSecret(generatedClientSecret));
            client.setRegistrationAccessToken(HandleTokenFactory.generateHandleToken());
            client.setIdTokenTokenBindingCnf(r.getIdTokenTokenBindingCnf());

            final Calendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
            client.setClientIdIssuedAt(calendar.getTime());

            if (appConfiguration.getDynamicRegistrationExpirationTime() > 0) { // #883 : expiration can be -1, mean does not expire
                calendar.add(Calendar.SECOND, appConfiguration.getDynamicRegistrationExpirationTime());
                client.setClientSecretExpiresAt(calendar.getTime());
                client.setExpirationDate(calendar.getTime());
                client.setTtl(appConfiguration.getDynamicRegistrationExpirationTime());
            }
            client.setDeletable(client.getClientSecretExpiresAt() != null);

            if (StringUtils.isBlank(r.getClientName()) && r.getRedirectUris() != null && !r.getRedirectUris().isEmpty()) {
                try {
                    URI redUri = new URI(r.getRedirectUris().get(0));
                    client.setClientName(redUri.getHost());
                } catch (Exception e) {
                    //ignore
                    log.error(e.getMessage(), e);
                    client.setClientName("Unknown");
                }
            }

            updateClientFromRequestObject(client, r, false);

            boolean registerClient = true;
            if (externalDynamicClientRegistrationService.isEnabled()) {
                registerClient = externalDynamicClientRegistrationService.executeExternalCreateClientMethods(r, client);
            }

            if (!registerClient) {
                log.trace("Client parameters are invalid, returns invalid_request error. External registration script returned false.");
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "External registration script returned false.");
            }

            Date currentTime = Calendar.getInstance().getTime();
            client.setLastAccessTime(currentTime);
            client.setLastLogonTime(currentTime);

            Boolean persistClientAuthorizations = appConfiguration.getDynamicRegistrationPersistClientAuthorizations();
            client.setPersistClientAuthorizations(persistClientAuthorizations != null ? persistClientAuthorizations : false);

            clientService.persist(client);

            JSONObject jsonObject = getJSONObject(client);
            builder.entity(jsonObject.toString(4).replace("\\/", "/"));

            log.info("Client registered: clientId = {}, applicationType = {}, clientName = {}, redirectUris = {}, sectorIdentifierUri = {}",
                    client.getClientId(), client.getApplicationType(), client.getClientName(), client.getRedirectUris(), client.getSectorIdentifierUri());

            oAuth2AuditLog.setClientId(client.getClientId());
            oAuth2AuditLog.setScope(clientScopesToString(client));
            oAuth2AuditLog.setSuccess(true);
        } catch (StringEncrypter.EncryptionException e) {
            builder = internalErrorResponse("Encryption exception occured.");
            log.error(e.getMessage(), e);
        } catch (JSONException e) {
            builder = internalErrorResponse("Failed to parse JSON.");
            log.error(e.getMessage(), e);
        } catch (WebApplicationException e) {
            log.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            builder = internalErrorResponse("Unknown.");
            log.error(e.getMessage(), e);
        }

        builder.cacheControl(ServerUtil.cacheControl(true, false));
        builder.header("Pragma", "no-cache");
        builder.type(MediaType.APPLICATION_JSON_TYPE);
        applicationAuditLogger.sendMessage(oAuth2AuditLog);
        return builder.build();
    }

    private JSONObject validateSoftwareStatement(HttpServletRequest httpServletRequest, JSONObject requestObject) {
        if (!requestObject.has(SOFTWARE_STATEMENT.toString())) {
            return null;
        }

        try {
            Jwt softwareStatement = Jwt.parse(requestObject.getString(SOFTWARE_STATEMENT.toString()));
            final SignatureAlgorithm signatureAlgorithm = softwareStatement.getHeader().getSignatureAlgorithm();

            final SoftwareStatementValidationType validationType = SoftwareStatementValidationType.fromString(appConfiguration.getSoftwareStatementValidationType());
            if (validationType == SoftwareStatementValidationType.NONE) {
                log.trace("software_statement validation was skipped due to `softwareStatementValidationType` configuration property set to none. (Not recommended.)");
                return softwareStatement.getClaims().toJsonObject();
            }

            if (validationType == SoftwareStatementValidationType.SCRIPT) {
                if (!externalDynamicClientRegistrationService.isEnabled()) {
                    log.error("Server is mis-configured. softwareStatementValidationType=script but there is no any Dynamic Client Registration script enabled.");
                    return null;
                }

                if (AlgorithmFamily.HMAC.equals(signatureAlgorithm.getFamily())) {

                    final String hmacSecret = externalDynamicClientRegistrationService.getSoftwareStatementHmacSecret(httpServletRequest, requestObject, softwareStatement);
                    if (StringUtils.isBlank(hmacSecret)) {
                        log.error("No hmacSecret provided in Dynamic Client Registration script (method getSoftwareStatementHmacSecret didn't return actual secret). ");
                        throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_SOFTWARE_STATEMENT, "");
                    }

                    if (!cryptoProvider.verifySignature(softwareStatement.getSigningInput(), softwareStatement.getEncodedSignature(), null, null, hmacSecret, signatureAlgorithm)) {
                        throw new InvalidJwtException("Invalid signature in the software statement");
                    }

                    return softwareStatement.getClaims().toJsonObject();
                }

                final JSONObject softwareStatementJwks = externalDynamicClientRegistrationService.getSoftwareStatementJwks(httpServletRequest, requestObject, softwareStatement);
                if (softwareStatementJwks == null) {
                    log.error("No jwks provided in Dynamic Client Registration script (method getSoftwareStatementJwks didn't return actual jwks). ");
                    throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_SOFTWARE_STATEMENT, "");
                }

                if (!cryptoProvider.verifySignature(softwareStatement.getSigningInput(), softwareStatement.getEncodedSignature(), softwareStatement.getHeader().getKeyId(), softwareStatementJwks, null, signatureAlgorithm)) {
                    throw new InvalidJwtException("Invalid signature in the software statement");
                }

                return softwareStatement.getClaims().toJsonObject();
            }

            if ((validationType == SoftwareStatementValidationType.JWKS_URI ||
                    validationType == SoftwareStatementValidationType.JWKS) &&
                    StringUtils.isBlank(appConfiguration.getSoftwareStatementValidationClaimName())) {
                log.error("softwareStatementValidationClaimName configuration property is not specified. Please specify claim name from software_statement which points to jwks (or jwks_uri).");
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_SOFTWARE_STATEMENT, "Failed to validate software statement");
            }

            String jwksUriClaim = null;
            if (validationType == SoftwareStatementValidationType.JWKS_URI) {
                jwksUriClaim = softwareStatement.getClaims().getClaimAsString(appConfiguration.getSoftwareStatementValidationClaimName());
            }

            String jwksClaim = null;
            if (validationType == SoftwareStatementValidationType.JWKS) {
                jwksClaim = softwareStatement.getClaims().getClaimAsString(appConfiguration.getSoftwareStatementValidationClaimName());
            }

            if (StringUtils.isBlank(jwksUriClaim) && StringUtils.isBlank(jwksClaim)) {
                final String msg = String.format("software_statement does not contain `%s` claim and thus is considered as invalid.", appConfiguration.getSoftwareStatementValidationClaimName());
                log.error(msg);
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_SOFTWARE_STATEMENT, msg);
            }

            JSONObject jwks = Strings.isNullOrEmpty(jwksUriClaim) ?
                    new JSONObject(jwksClaim) :
                    JwtUtil.getJSONWebKeys(jwksUriClaim);

            boolean validSignature = cryptoProvider.verifySignature(softwareStatement.getSigningInput(),
                    softwareStatement.getEncodedSignature(),
                    softwareStatement.getHeader().getKeyId(), jwks, null, signatureAlgorithm);

            if (!validSignature) {
                throw new InvalidJwtException("Invalid cryptographic segment in the software statement");
            }

            return softwareStatement.getClaims().toJsonObject();
        } catch (Exception e) {
            final String msg = "Invalid software_statement.";
            log.error(msg, e);
            throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_SOFTWARE_STATEMENT, msg);
        }
    }

    private Response.ResponseBuilder internalErrorResponse(String reason) {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_CLIENT_METADATA, reason));
    }

    // yuriyz - ATTENTION : this method is used for both registration and update client metadata cases, therefore any logic here
    // will be applied for both cases.
    private void updateClientFromRequestObject(Client p_client, RegisterRequest requestObject, boolean update) throws JSONException {

        JsonApplier.getInstance().transfer(requestObject, p_client);
        JsonApplier.getInstance().transfer(requestObject, p_client.getAttributes());

        List<String> redirectUris = requestObject.getRedirectUris();
        if (redirectUris != null && !redirectUris.isEmpty()) {
            redirectUris = new ArrayList<>(new HashSet<>(redirectUris)); // Remove repeated elements
            p_client.setRedirectUris(redirectUris.toArray(new String[redirectUris.size()]));
        }
        List<String> claimsRedirectUris = requestObject.getClaimsRedirectUris();
        if (claimsRedirectUris != null && !claimsRedirectUris.isEmpty()) {
            claimsRedirectUris = new ArrayList<>(new HashSet<>(claimsRedirectUris)); // Remove repeated elements
            p_client.setClaimRedirectUris(claimsRedirectUris.toArray(new String[claimsRedirectUris.size()]));
        }
        if (requestObject.getApplicationType() != null) {
            p_client.setApplicationType(requestObject.getApplicationType().toString());
        }
        if (StringUtils.isNotBlank(requestObject.getClientName())) {
            p_client.setClientName(requestObject.getClientName());
        }
        if (StringUtils.isNotBlank(requestObject.getSectorIdentifierUri())) {
            p_client.setSectorIdentifierUri(requestObject.getSectorIdentifierUri());
        }

        Set<ResponseType> responseTypeSet = new HashSet<>();
        responseTypeSet.addAll(requestObject.getResponseTypes());

        Set<GrantType> grantTypeSet = new HashSet<>();
        grantTypeSet.addAll(requestObject.getGrantTypes());

        if (isTrue(appConfiguration.getGrantTypesAndResponseTypesAutofixEnabled())) {
            if (appConfiguration.getClientRegDefaultToCodeFlowWithRefresh()) {
                if (responseTypeSet.size() == 0 && grantTypeSet.size() == 0) {
                    responseTypeSet.add(ResponseType.CODE);
                }
                if (responseTypeSet.contains(ResponseType.CODE)) {
                    grantTypeSet.add(GrantType.AUTHORIZATION_CODE);
                    grantTypeSet.add(GrantType.REFRESH_TOKEN);
                }
                if (grantTypeSet.contains(GrantType.AUTHORIZATION_CODE)) {
                    responseTypeSet.add(ResponseType.CODE);
                    grantTypeSet.add(GrantType.REFRESH_TOKEN);
                }
            }
            if (responseTypeSet.contains(ResponseType.TOKEN) || responseTypeSet.contains(ResponseType.ID_TOKEN)) {
                grantTypeSet.add(GrantType.IMPLICIT);
            }
            if (grantTypeSet.contains(GrantType.IMPLICIT)) {
                responseTypeSet.add(ResponseType.TOKEN);
            }
        }

        Set<Set<ResponseType>> responseTypesSupported = appConfiguration.getResponseTypesSupported();
        Set<GrantType> grantTypesSupported = appConfiguration.getGrantTypesSupported();

        if (!responseTypesSupported.contains(responseTypeSet)) {
            responseTypeSet.clear();
        }

        grantTypeSet.retainAll(grantTypesSupported);

        Set<GrantType> dynamicGrantTypeDefault = appConfiguration.getDynamicGrantTypeDefault();
        grantTypeSet.retainAll(dynamicGrantTypeDefault);

        if (!update || requestObject.getResponseTypes().size() > 0) {
            p_client.setResponseTypes(responseTypeSet.toArray(new ResponseType[responseTypeSet.size()]));
        }
        if (!update) {
            p_client.setGrantTypes(grantTypeSet.toArray(new GrantType[grantTypeSet.size()]));
        } else if (appConfiguration.getEnableClientGrantTypeUpdate() && requestObject.getGrantTypes().size() > 0) {
            p_client.setGrantTypes(grantTypeSet.toArray(new GrantType[grantTypeSet.size()]));
        }

        List<String> contacts = requestObject.getContacts();
        if (contacts != null && !contacts.isEmpty()) {
            contacts = new ArrayList<>(new HashSet<>(contacts)); // Remove repeated elements
            p_client.setContacts(contacts.toArray(new String[contacts.size()]));
        }
        if (StringUtils.isNotBlank(requestObject.getLogoUri())) {
            p_client.setLogoUri(requestObject.getLogoUri());
        }
        if (StringUtils.isNotBlank(requestObject.getClientUri())) {
            p_client.setClientUri(requestObject.getClientUri());
        }
        if (StringUtils.isNotBlank(requestObject.getPolicyUri())) {
            p_client.setPolicyUri(requestObject.getPolicyUri());
        }
        if (StringUtils.isNotBlank(requestObject.getTosUri())) {
            p_client.setTosUri(requestObject.getTosUri());
        }
        if (StringUtils.isNotBlank(requestObject.getJwksUri())) {
            p_client.setJwksUri(requestObject.getJwksUri());
        }
        if (StringUtils.isNotBlank(requestObject.getJwks())) {
            p_client.setJwks(requestObject.getJwks());
        }
        if (requestObject.getSubjectType() != null) {
            p_client.setSubjectType(requestObject.getSubjectType().toString());
        }
        if (requestObject.getRptAsJwt() != null) {
            p_client.setRptAsJwt(requestObject.getRptAsJwt());
        }
        if (requestObject.getAccessTokenAsJwt() != null) {
            p_client.setAccessTokenAsJwt(requestObject.getAccessTokenAsJwt());
        }
        if (requestObject.getTlsClientAuthSubjectDn() != null) {
            p_client.getAttributes().setTlsClientAuthSubjectDn(requestObject.getTlsClientAuthSubjectDn());
        }
        if (requestObject.getAllowSpontaneousScopes() != null) {
            p_client.getAttributes().setAllowSpontaneousScopes(requestObject.getAllowSpontaneousScopes());
        }
        if (requestObject.getSpontaneousScopes() != null) {
            p_client.getAttributes().setSpontaneousScopes(requestObject.getSpontaneousScopes());
        }
        if (requestObject.getRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims() != null) {
            p_client.getAttributes().setRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims(requestObject.getRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims());
        }
        if (requestObject.getKeepClientAuthorizationAfterExpiration() != null) {
            p_client.getAttributes().setKeepClientAuthorizationAfterExpiration(requestObject.getKeepClientAuthorizationAfterExpiration());
        }
        if (requestObject.getAccessTokenSigningAlg() != null) {
            p_client.setAccessTokenSigningAlg(requestObject.getAccessTokenSigningAlg().toString());
        }
        if (requestObject.getIdTokenSignedResponseAlg() != null) {
            p_client.setIdTokenSignedResponseAlg(requestObject.getIdTokenSignedResponseAlg().toString());
        }
        if (requestObject.getIdTokenEncryptedResponseAlg() != null) {
            p_client.setIdTokenEncryptedResponseAlg(requestObject.getIdTokenEncryptedResponseAlg().toString());
        }
        if (requestObject.getIdTokenEncryptedResponseEnc() != null) {
            p_client.setIdTokenEncryptedResponseEnc(requestObject.getIdTokenEncryptedResponseEnc().toString());
        }
        if (requestObject.getUserInfoSignedResponseAlg() != null) {
            p_client.setUserInfoSignedResponseAlg(requestObject.getUserInfoSignedResponseAlg().toString());
        }
        if (requestObject.getUserInfoEncryptedResponseAlg() != null) {
            p_client.setUserInfoEncryptedResponseAlg(requestObject.getUserInfoEncryptedResponseAlg().toString());
        }
        if (requestObject.getUserInfoEncryptedResponseEnc() != null) {
            p_client.setUserInfoEncryptedResponseEnc(requestObject.getUserInfoEncryptedResponseEnc().toString());
        }
        if (requestObject.getRequestObjectSigningAlg() != null) {
            p_client.setRequestObjectSigningAlg(requestObject.getRequestObjectSigningAlg().toString());
        }
        if (requestObject.getRequestObjectEncryptionAlg() != null) {
            p_client.setRequestObjectEncryptionAlg(requestObject.getRequestObjectEncryptionAlg().toString());
        }
        if (requestObject.getRequestObjectEncryptionEnc() != null) {
            p_client.setRequestObjectEncryptionEnc(requestObject.getRequestObjectEncryptionEnc().toString());
        }
        if (requestObject.getTokenEndpointAuthMethod() != null) {
            p_client.setTokenEndpointAuthMethod(requestObject.getTokenEndpointAuthMethod().toString());
        } else { // If omitted, the default is client_secret_basic
            p_client.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_BASIC.toString());
        }
        if (requestObject.getTokenEndpointAuthSigningAlg() != null) {
            p_client.setTokenEndpointAuthSigningAlg(requestObject.getTokenEndpointAuthSigningAlg().toString());
        }
        if (requestObject.getDefaultMaxAge() != null) {
            p_client.setDefaultMaxAge(requestObject.getDefaultMaxAge());
        }
        if (requestObject.getRequireAuthTime() != null) {
            p_client.setRequireAuthTime(requestObject.getRequireAuthTime());
        }
        List<String> defaultAcrValues = requestObject.getDefaultAcrValues();
        if (defaultAcrValues != null && !defaultAcrValues.isEmpty()) {
            defaultAcrValues = new ArrayList<>(new HashSet<>(defaultAcrValues)); // Remove repeated elements
            p_client.setDefaultAcrValues(defaultAcrValues.toArray(new String[defaultAcrValues.size()]));
        }
        if (StringUtils.isNotBlank(requestObject.getInitiateLoginUri())) {
            p_client.setInitiateLoginUri(requestObject.getInitiateLoginUri());
        }
        List<String> postLogoutRedirectUris = requestObject.getPostLogoutRedirectUris();
        if (postLogoutRedirectUris != null && !postLogoutRedirectUris.isEmpty()) {
            postLogoutRedirectUris = new ArrayList<>(new HashSet<>(postLogoutRedirectUris)); // Remove repeated elements
            p_client.setPostLogoutRedirectUris(postLogoutRedirectUris.toArray(new String[postLogoutRedirectUris.size()]));
        }

        if (requestObject.getFrontChannelLogoutUris() != null && !requestObject.getFrontChannelLogoutUris().isEmpty()) {
            p_client.setFrontChannelLogoutUri(requestObject.getFrontChannelLogoutUris().toArray(new String[requestObject.getFrontChannelLogoutUris().size()]));
        }
        p_client.setFrontChannelLogoutSessionRequired(requestObject.getFrontChannelLogoutSessionRequired());

        if (requestObject.getBackchannelLogoutUris() != null && !requestObject.getBackchannelLogoutUris().isEmpty()) {
            p_client.getAttributes().setBackchannelLogoutUri(requestObject.getBackchannelLogoutUris());
        }
        p_client.getAttributes().setBackchannelLogoutSessionRequired(requestObject.getBackchannelLogoutSessionRequired());

        List<String> requestUris = requestObject.getRequestUris();
        if (requestUris != null && !requestUris.isEmpty()) {
            requestUris = new ArrayList<>(new HashSet<>(requestUris)); // Remove repeated elements
            p_client.setRequestUris(requestUris.toArray(new String[requestUris.size()]));
        }

        List<String> authorizedOrigins = requestObject.getAuthorizedOrigins();
        if (authorizedOrigins != null && !authorizedOrigins.isEmpty()) {
            authorizedOrigins = new ArrayList<>(new HashSet<>(authorizedOrigins)); // Remove repeated elements
            p_client.setAuthorizedOrigins(authorizedOrigins.toArray(new String[authorizedOrigins.size()]));
        }

        List<String> scopes = requestObject.getScope();
        if (grantTypeSet.contains(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS) && !appConfiguration.getDynamicRegistrationAllowedPasswordGrantScopes().isEmpty()) {
            scopes = Lists.newArrayList(scopes);
            scopes.retainAll(appConfiguration.getDynamicRegistrationAllowedPasswordGrantScopes());
        }
        List<String> scopesDn;
        if (scopes != null && !scopes.isEmpty()
                && appConfiguration.getDynamicRegistrationScopesParamEnabled() != null
                && appConfiguration.getDynamicRegistrationScopesParamEnabled()) {
            List<String> defaultScopes = scopeService.getDefaultScopesDn();
            List<String> requestedScopes = scopeService.getScopesDn(scopes);
            Set<String> allowedScopes = new HashSet<>();

            for (String requestedScope : requestedScopes) {
                if (defaultScopes.contains(requestedScope)) {
                    allowedScopes.add(requestedScope);
                }
            }

            scopesDn = new ArrayList<>(allowedScopes);
            p_client.setScopes(scopesDn.toArray(new String[scopesDn.size()]));
        } else if (BooleanUtils.isFalse(appConfiguration.getDynamicRegistrationDisableFallbackScopesAssigning())) {
            scopesDn = scopeService.getDefaultScopesDn();
            p_client.setScopes(scopesDn.toArray(new String[scopesDn.size()]));
        }

        List<String> claims = requestObject.getClaims();
        if (claims != null && !claims.isEmpty()) {
            List<String> claimsDn = attributeService.getAttributesDn(claims);
            p_client.setClaims(claimsDn.toArray(new String[claimsDn.size()]));
        }

        if (requestObject.getJsonObject() != null) {
            // Custom params
            putCustomStuffIntoObject(p_client, requestObject.getJsonObject());
        }

        if (requestObject.getAccessTokenLifetime() != null) {
            p_client.setAccessTokenLifetime(requestObject.getAccessTokenLifetime());
        }

        if (StringUtils.isNotBlank(requestObject.getSoftwareId())) {
            p_client.setSoftwareId(requestObject.getSoftwareId());
        }
        if (StringUtils.isNotBlank(requestObject.getSoftwareVersion())) {
            p_client.setSoftwareVersion(requestObject.getSoftwareVersion());
        }
        if (StringUtils.isNotBlank(requestObject.getSoftwareStatement())) {
            p_client.setSoftwareStatement(requestObject.getSoftwareStatement());
        }

        cibaRegisterClientMetadataService.updateClient(p_client, requestObject.getBackchannelTokenDeliveryMode(),
                requestObject.getBackchannelClientNotificationEndpoint(), requestObject.getBackchannelAuthenticationRequestSigningAlg(),
                requestObject.getBackchannelUserCodeParameter());
    }

    @Override
    public Response requestClientUpdate(String requestParams, String clientId, @HeaderParam("Authorization") String authorization, @Context HttpServletRequest httpRequest, @Context SecurityContext securityContext) {
        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(httpRequest), Action.CLIENT_UPDATE);
        oAuth2AuditLog.setClientId(clientId);
        try {
            log.debug("Attempting to UPDATE client, client_id: {}, requestParams = {}, isSecure = {}",
                    clientId, requestParams, securityContext.isSecure());
            final String accessToken = tokenService.getToken(authorization);

            if (StringUtils.isNotBlank(accessToken) && StringUtils.isNotBlank(clientId) && StringUtils.isNotBlank(requestParams)) {
                JSONObject requestObject = new JSONObject(requestParams);
                final JSONObject softwareStatement = validateSoftwareStatement(httpRequest, requestObject);
                if (softwareStatement != null) {
                    log.trace("Override request parameters by software_statement");
                    for (String key : softwareStatement.keySet()) {
                        requestObject.putOpt(key, softwareStatement.get(key));
                    }
                }

                final RegisterRequest request = RegisterRequest.fromJson(requestObject, appConfiguration.getLegacyDynamicRegistrationScopeParam());
                if (request != null) {
                    boolean redirectUrisValidated = true;
                    if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
                        redirectUrisValidated = registerParamsValidator.validateRedirectUris(
                                request.getGrantTypes(), request.getResponseTypes(),
                                request.getApplicationType(), request.getSubjectType(),
                                request.getRedirectUris(), request.getSectorIdentifierUri());
                    }

                    if (redirectUrisValidated) {
                        if (!cibaRegisterParamsValidatorService.validateParams(
                                request.getBackchannelTokenDeliveryMode(),
                                request.getBackchannelClientNotificationEndpoint(),
                                request.getBackchannelAuthenticationRequestSigningAlg(),
                                request.getBackchannelUserCodeParameter(),
                                request.getGrantTypes(),
                                request.getSubjectType(),
                                request.getSectorIdentifierUri(),
                                request.getJwks(),
                                request.getJwksUri()
                        )) {
                            return Response.status(Response.Status.BAD_REQUEST).
                                    entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_CLIENT_METADATA,
                                            "Invalid Client Metadata registering to use CIBA.")).build();
                        }

                        if (request.getSubjectType() != null
                                && !appConfiguration.getSubjectTypesSupported().contains(request.getSubjectType().toString())) {
                            log.debug("Client UPDATE : parameter subject_type is invalid. Returns BAD_REQUEST response.");
                            applicationAuditLogger.sendMessage(oAuth2AuditLog);
                            return Response.status(Response.Status.BAD_REQUEST).
                                    entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_CLIENT_METADATA, "subject_type is invalid.")).build();
                        }

                        final Client client = clientService.getClient(clientId, accessToken);
                        if (client != null) {
                            updateClientFromRequestObject(client, request, true);

                            boolean updateClient = true;
                            if (externalDynamicClientRegistrationService.isEnabled()) {
                                updateClient = externalDynamicClientRegistrationService.executeExternalUpdateClientMethods(request, client);
                            }

                            if (updateClient) {
                                clientService.merge(client);

                                oAuth2AuditLog.setScope(clientScopesToString(client));
                                oAuth2AuditLog.setSuccess(true);
                                applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                return Response.status(Response.Status.OK).entity(clientAsEntity(client)).build();
                            } else {
                                log.trace("The Access Token is not valid for the Client ID, returns invalid_token error.");
                                applicationAuditLogger.sendMessage(oAuth2AuditLog);
                                return Response.status(Response.Status.BAD_REQUEST).
                                        type(MediaType.APPLICATION_JSON_TYPE).
                                        entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_TOKEN, "External registration script returned false.")).build();
                            }
                        } else {
                            log.trace("The Access Token is not valid for the Client ID, returns invalid_token error.");
                            applicationAuditLogger.sendMessage(oAuth2AuditLog);
                            return Response.status(Response.Status.BAD_REQUEST).
                                    type(MediaType.APPLICATION_JSON_TYPE).
                                    entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_TOKEN, "The Access Token is not valid for the Client ID.")).build();
                        }
                    }
                }
            }

            log.debug("Client UPDATE : parameters are invalid. Returns BAD_REQUEST response.");
            applicationAuditLogger.sendMessage(oAuth2AuditLog);
            return Response.status(Response.Status.BAD_REQUEST).
                    entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Unknown.")).build();

        } catch (WebApplicationException e) {
            log.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        applicationAuditLogger.sendMessage(oAuth2AuditLog);
        return internalErrorResponse("Unknown.").build();
    }

    @Override
    public Response requestClientRead(String clientId, String authorization, HttpServletRequest httpRequest,
                                      SecurityContext securityContext) {
        String accessToken = tokenService.getToken(authorization);
        log.debug("Attempting to read client: clientId = {}, registrationAccessToken = {} isSecure = {}",
                clientId, accessToken, securityContext.isSecure());
        Response.ResponseBuilder builder = Response.ok();

        OAuth2AuditLog oAuth2AuditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(httpRequest), Action.CLIENT_READ);
        oAuth2AuditLog.setClientId(clientId);
        try {
            if (appConfiguration.getDynamicRegistrationEnabled()) {
                if (registerParamsValidator.validateParamsClientRead(clientId, accessToken)) {
                    Client client = clientService.getClient(clientId, accessToken);
                    if (client != null) {
                        oAuth2AuditLog.setScope(clientScopesToString(client));
                        oAuth2AuditLog.setSuccess(true);
                        builder.entity(clientAsEntity(client));
                    } else {
                        log.trace("The Access Token is not valid for the Client ID, returns invalid_token error.");
                        builder = Response.status(Response.Status.BAD_REQUEST.getStatusCode()).type(MediaType.APPLICATION_JSON_TYPE);
                        builder.entity(errorResponseFactory.errorAsJson(RegisterErrorResponseType.INVALID_TOKEN, "The Access Token is not valid for the Client"));
                    }
                } else {
                    log.trace("Client ID or Access Token is not valid.");
                    throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Client ID or Access Token is not valid.");
                }
            } else {
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.ACCESS_DENIED, "Dynamic registration is disabled.");
            }
        } catch (JSONException e) {
            log.error(e.getMessage(), e);
            throw errorResponseFactory.createWebApplicationException(Response.Status.INTERNAL_SERVER_ERROR, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Failed to parse json.");
        } catch (StringEncrypter.EncryptionException e) {
            log.error(e.getMessage(), e);
            throw errorResponseFactory.createWebApplicationException(Response.Status.INTERNAL_SERVER_ERROR, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Encryption exception occurred.");
        }

        builder.cacheControl(ServerUtil.cacheControl(true, false));
        builder.header("Pragma", "no-cache");
        applicationAuditLogger.sendMessage(oAuth2AuditLog);
        return builder.build();
    }

    private String clientAsEntity(Client p_client) throws JSONException, StringEncrypter.EncryptionException {
        final JSONObject jsonObject = getJSONObject(p_client);
        return jsonObject.toString(4).replace("\\/", "/");
    }

    private JSONObject getJSONObject(Client client) throws JSONException, StringEncrypter.EncryptionException {
        JSONObject responseJsonObject = new JSONObject();

        JsonApplier.getInstance().apply(client, responseJsonObject);
        JsonApplier.getInstance().apply(client.getAttributes(), responseJsonObject);

        Util.addToJSONObjectIfNotNull(responseJsonObject, RegisterResponseParam.CLIENT_ID.toString(), client.getClientId());
        if (appConfiguration.getReturnClientSecretOnRead()) {
            Util.addToJSONObjectIfNotNull(responseJsonObject, CLIENT_SECRET.toString(), clientService.decryptSecret(client.getClientSecret()));
        }
        Util.addToJSONObjectIfNotNull(responseJsonObject, RegisterResponseParam.REGISTRATION_ACCESS_TOKEN.toString(), client.getRegistrationAccessToken());
        Util.addToJSONObjectIfNotNull(responseJsonObject, REGISTRATION_CLIENT_URI.toString(),
                appConfiguration.getRegistrationEndpoint() + "?" +
                        RegisterResponseParam.CLIENT_ID.toString() + "=" + client.getClientId());
        responseJsonObject.put(CLIENT_ID_ISSUED_AT.toString(), client.getClientIdIssuedAt().getTime() / 1000);
        responseJsonObject.put(CLIENT_SECRET_EXPIRES_AT.toString(), client.getClientSecretExpiresAt() != null && client.getClientSecretExpiresAt().getTime() > 0 ?
                client.getClientSecretExpiresAt().getTime() / 1000 : 0);

        Util.addToJSONObjectIfNotNull(responseJsonObject, REDIRECT_URIS.toString(), client.getRedirectUris());
        Util.addToJSONObjectIfNotNull(responseJsonObject, CLAIMS_REDIRECT_URIS.toString(), client.getClaimRedirectUris());
        Util.addToJSONObjectIfNotNull(responseJsonObject, RESPONSE_TYPES.toString(), ResponseType.toStringArray(client.getResponseTypes()));
        Util.addToJSONObjectIfNotNull(responseJsonObject, GRANT_TYPES.toString(), GrantType.toStringArray(client.getGrantTypes()));
        Util.addToJSONObjectIfNotNull(responseJsonObject, APPLICATION_TYPE.toString(), client.getApplicationType());
        Util.addToJSONObjectIfNotNull(responseJsonObject, CONTACTS.toString(), client.getContacts());
        Util.addToJSONObjectIfNotNull(responseJsonObject, CLIENT_NAME.toString(), client.getClientName());
        Util.addToJSONObjectIfNotNull(responseJsonObject, LOGO_URI.toString(), client.getLogoUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, CLIENT_URI.toString(), client.getClientUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, POLICY_URI.toString(), client.getPolicyUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, TOS_URI.toString(), client.getTosUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, JWKS_URI.toString(), client.getJwksUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, SECTOR_IDENTIFIER_URI.toString(), client.getSectorIdentifierUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, SUBJECT_TYPE.toString(), client.getSubjectType());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ID_TOKEN_SIGNED_RESPONSE_ALG.toString(), client.getIdTokenSignedResponseAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ID_TOKEN_ENCRYPTED_RESPONSE_ALG.toString(), client.getIdTokenEncryptedResponseAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ID_TOKEN_ENCRYPTED_RESPONSE_ENC.toString(), client.getIdTokenEncryptedResponseEnc());
        Util.addToJSONObjectIfNotNull(responseJsonObject, USERINFO_SIGNED_RESPONSE_ALG.toString(), client.getUserInfoSignedResponseAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, USERINFO_ENCRYPTED_RESPONSE_ALG.toString(), client.getUserInfoEncryptedResponseAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, USERINFO_ENCRYPTED_RESPONSE_ENC.toString(), client.getUserInfoEncryptedResponseEnc());
        Util.addToJSONObjectIfNotNull(responseJsonObject, REQUEST_OBJECT_SIGNING_ALG.toString(), client.getRequestObjectSigningAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, REQUEST_OBJECT_ENCRYPTION_ALG.toString(), client.getRequestObjectEncryptionAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, REQUEST_OBJECT_ENCRYPTION_ENC.toString(), client.getRequestObjectEncryptionEnc());
        Util.addToJSONObjectIfNotNull(responseJsonObject, TOKEN_ENDPOINT_AUTH_METHOD.toString(), client.getTokenEndpointAuthMethod());
        Util.addToJSONObjectIfNotNull(responseJsonObject, TOKEN_ENDPOINT_AUTH_SIGNING_ALG.toString(), client.getTokenEndpointAuthSigningAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, DEFAULT_MAX_AGE.toString(), client.getDefaultMaxAge());
        Util.addToJSONObjectIfNotNull(responseJsonObject, REQUIRE_AUTH_TIME.toString(), client.getRequireAuthTime());
        Util.addToJSONObjectIfNotNull(responseJsonObject, DEFAULT_ACR_VALUES.toString(), client.getDefaultAcrValues());
        Util.addToJSONObjectIfNotNull(responseJsonObject, INITIATE_LOGIN_URI.toString(), client.getInitiateLoginUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, POST_LOGOUT_REDIRECT_URIS.toString(), client.getPostLogoutRedirectUris());
        Util.addToJSONObjectIfNotNull(responseJsonObject, REQUEST_URIS.toString(), client.getRequestUris());
        Util.addToJSONObjectIfNotNull(responseJsonObject, AUTHORIZED_ORIGINS.toString(), client.getAuthorizedOrigins());
        Util.addToJSONObjectIfNotNull(responseJsonObject, RPT_AS_JWT.toString(), client.isRptAsJwt());
        Util.addToJSONObjectIfNotNull(responseJsonObject, TLS_CLIENT_AUTH_SUBJECT_DN.toString(), client.getAttributes().getTlsClientAuthSubjectDn());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ALLOW_SPONTANEOUS_SCOPES.toString(), client.getAttributes().getAllowSpontaneousScopes());
        Util.addToJSONObjectIfNotNull(responseJsonObject, SPONTANEOUS_SCOPES.toString(), client.getAttributes().getSpontaneousScopes());
        Util.addToJSONObjectIfNotNull(responseJsonObject, RUN_INTROSPECTION_SCRIPT_BEFORE_ACCESS_TOKEN_CREATION_AS_JWT_AND_INCLUDE_CLAIMS.toString(), client.getAttributes().getRunIntrospectionScriptBeforeAccessTokenAsJwtCreationAndIncludeClaims());
        Util.addToJSONObjectIfNotNull(responseJsonObject, KEEP_CLIENT_AUTHORIZATION_AFTER_EXPIRATION.toString(), client.getAttributes().getKeepClientAuthorizationAfterExpiration());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ACCESS_TOKEN_AS_JWT.toString(), client.isAccessTokenAsJwt());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ACCESS_TOKEN_SIGNING_ALG.toString(), client.getAccessTokenSigningAlg());
        Util.addToJSONObjectIfNotNull(responseJsonObject, ACCESS_TOKEN_LIFETIME.toString(), client.getAccessTokenLifetime());
        Util.addToJSONObjectIfNotNull(responseJsonObject, SOFTWARE_ID.toString(), client.getSoftwareId());
        Util.addToJSONObjectIfNotNull(responseJsonObject, SOFTWARE_VERSION.toString(), client.getSoftwareVersion());
        Util.addToJSONObjectIfNotNull(responseJsonObject, SOFTWARE_STATEMENT.toString(), client.getSoftwareStatement());

        if (!Util.isNullOrEmpty(client.getJwks())) {
            Util.addToJSONObjectIfNotNull(responseJsonObject, JWKS.toString(), new JSONObject(client.getJwks()));
        }

        // Logout params
        Util.addToJSONObjectIfNotNull(responseJsonObject, FRONT_CHANNEL_LOGOUT_URI.toString(), client.getFrontChannelLogoutUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, FRONT_CHANNEL_LOGOUT_SESSION_REQUIRED.toString(), client.getFrontChannelLogoutSessionRequired());
        Util.addToJSONObjectIfNotNull(responseJsonObject, BACKCHANNEL_LOGOUT_URI.toString(), client.getAttributes().getBackchannelLogoutUri());
        Util.addToJSONObjectIfNotNull(responseJsonObject, BACKCHANNEL_LOGOUT_SESSION_REQUIRED.toString(), client.getAttributes().getBackchannelLogoutSessionRequired());

        // Custom Params
        String[] scopeNames = null;
        String[] scopeDns = client.getScopes();
        if (scopeDns != null) {
            scopeNames = new String[scopeDns.length];
            for (int i = 0; i < scopeDns.length; i++) {
                Scope scope = scopeService.getScopeByDn(scopeDns[i]);
                scopeNames[i] = scope.getId();
            }
        }

        if (appConfiguration.getLegacyDynamicRegistrationScopeParam()) {
            Util.addToJSONObjectIfNotNull(responseJsonObject, SCOPES.toString(), scopeNames);
        } else {
            Util.addToJSONObjectIfNotNull(responseJsonObject, SCOPE.toString(), implode(scopeNames, " "));
        }

        String[] claimNames = null;
        String[] claimDns = client.getClaims();
        if (claimDns != null) {
            claimNames = new String[claimDns.length];
            for (int i = 0; i < claimDns.length; i++) {
                GluuAttribute gluuAttribute = attributeService.getAttributeByDn(claimDns[i]);
                claimNames[i] = gluuAttribute.getOxAuthClaimName();
            }
        }

        putCustomAttributesInResponse(client, responseJsonObject);

        if (claimNames != null && claimNames.length > 0) {
            Util.addToJSONObjectIfNotNull(responseJsonObject, CLAIMS.toString(), implode(claimNames, " "));
        }

        cibaRegisterClientResponseService.updateResponse(responseJsonObject, client);

        return responseJsonObject;
    }

    private void putCustomAttributesInResponse(Client client,  JSONObject responseJsonObject) {
        final List<String> allowedCustomAttributeNames = appConfiguration.getDynamicRegistrationCustomAttributes();
        final List<CustomAttribute> customAttributes = client.getCustomAttributes();
        if (allowedCustomAttributeNames == null || allowedCustomAttributeNames.isEmpty() || customAttributes == null) {
            return;
        }

        for (CustomAttribute attribute : customAttributes) {
            if (!allowedCustomAttributeNames.contains(attribute.getName()))
                continue;

            if (attribute.isMultiValued()) {
                Util.addToJSONObjectIfNotNull(responseJsonObject, attribute.getName(), attribute.getValues());
            } else {
                Util.addToJSONObjectIfNotNull(responseJsonObject, attribute.getName(), attribute.getValue());
            }
        }
    }

    /**
     * Puts custom object class and custom attributes in client object for persistence.
     *
     * @param p_client        client object
     * @param p_requestObject request object
     */
    private void putCustomStuffIntoObject(Client p_client, JSONObject p_requestObject) throws JSONException {
        // custom object class
        final String customOC = appConfiguration.getDynamicRegistrationCustomObjectClass();
        if (StringUtils.isNotBlank(customOC)) {
            p_client.setCustomObjectClasses(new String[]{customOC});
        }

        // custom attributes (custom attributes must be in custom object class)
        final List<String> attrList = appConfiguration.getDynamicRegistrationCustomAttributes();
        if (attrList != null && !attrList.isEmpty()) {
            for (String attr : attrList) {
                if (p_requestObject.has(attr)) {
                    final JSONArray parameterValuesJsonArray = p_requestObject.optJSONArray(attr);
                    final List<String> parameterValues = parameterValuesJsonArray != null ?
                            toList(parameterValuesJsonArray) :
                            Arrays.asList(p_requestObject.getString(attr));
                    if (parameterValues != null && !parameterValues.isEmpty()) {
                        try {
                            boolean processed = processApplicationAttributes(p_client, attr, parameterValues);
                            if (!processed) {
                                p_client.getCustomAttributes().add(new CustomAttribute(attr, parameterValues));
                            }
                        } catch (Exception e) {
                            log.debug(e.getMessage(), e);
                        }
                    }
                }
            }
        }
    }

    private boolean processApplicationAttributes(Client p_client, String attr, final List<String> parameterValues) {
        if (StringHelper.equalsIgnoreCase("oxAuthTrustedClient", attr)) {
            boolean trustedClient = StringHelper.toBoolean(parameterValues.get(0), false);
            p_client.setTrustedClient(trustedClient);

            return true;
        } else if (StringHelper.equalsIgnoreCase("oxIncludeClaimsInIdToken", attr)) {
            boolean includeClaimsInIdToken = StringHelper.toBoolean(parameterValues.get(0), false);
            p_client.setIncludeClaimsInIdToken(includeClaimsInIdToken);

            return true;
        }

        return false;
    }

    private String clientScopesToString(Client client) {
        String[] scopeDns = client.getScopes();
        if (scopeDns != null) {
            String[] scopeNames = new String[scopeDns.length];
            for (int i = 0; i < scopeDns.length; i++) {
                Scope scope = scopeService.getScopeByDn(scopeDns[i]);
                scopeNames[i] = scope.getId();
            }
            return StringUtils.join(scopeNames, " ");
        }
        return null;
    }

    @Override
    public Response delete(String clientId, String authorization, HttpServletRequest httpRequest, SecurityContext securityContext) {
        OAuth2AuditLog auditLog = new OAuth2AuditLog(ServerUtil.getIpAddress(httpRequest), Action.CLIENT_DELETE);
        auditLog.setClientId(clientId);

        try {
            String accessToken = tokenService.getToken(authorization);

            log.debug("Attempting to delete client: clientId = {0}, registrationAccessToken = {1} isSecure = {2}",
                    clientId, accessToken, securityContext.isSecure());

            if (!appConfiguration.getDynamicRegistrationEnabled()) {
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.ACCESS_DENIED, "Dynamic registration is disabled.");
            }

            if (!registerParamsValidator.validateParamsClientRead(clientId, accessToken)) {
                log.trace("Client parameters are invalid.");
                throw errorResponseFactory.createWebApplicationException(Response.Status.BAD_REQUEST, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "");
            }

            Client client = clientService.getClient(clientId, accessToken);
            if (client == null) {
                throw errorResponseFactory.createWebApplicationException(Response.Status.UNAUTHORIZED, RegisterErrorResponseType.INVALID_TOKEN, "");
            }

            clientService.remove(client);
            auditLog.setSuccess(true);

            return Response
                    .status(Response.Status.NO_CONTENT)
                    .cacheControl(ServerUtil.cacheControl(true, false))
                    .header("Pragma", "no-cache").build();
        } catch (WebApplicationException e) {
            if (e.getResponse() != null) {
                return e.getResponse();
            }
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw errorResponseFactory.createWebApplicationException(Response.Status.INTERNAL_SERVER_ERROR, RegisterErrorResponseType.INVALID_CLIENT_METADATA, "Failed to process request.");
        } finally {
            applicationAuditLogger.sendMessage(auditLog);
        }
    }

}