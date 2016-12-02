/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.ws.rs;

import com.google.common.collect.Lists;
import org.codehaus.jettison.json.JSONArray;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseTest;
import org.xdi.oxauth.client.RegisterClient;
import org.xdi.oxauth.client.RegisterRequest;
import org.xdi.oxauth.client.RegisterResponse;
import org.xdi.oxauth.model.common.AuthenticationMethod;
import org.xdi.oxauth.model.common.SubjectType;
import org.xdi.oxauth.model.crypto.encryption.BlockEncryptionAlgorithm;
import org.xdi.oxauth.model.crypto.encryption.KeyEncryptionAlgorithm;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.register.ApplicationType;
import org.xdi.oxauth.model.util.StringUtils;

import javax.ws.rs.HttpMethod;
import java.util.*;

import static org.testng.Assert.*;
import static org.xdi.oxauth.model.register.RegisterRequestParam.*;

/**
 * Functional tests for Client Registration Web Services (HTTP)
 *
 * @author Javier Rojas Blum
 * @author Yuriy Zabrovarnyy
 * @version November 2, 2016
 */
public class RegistrationRestWebServiceHttpTest extends BaseTest {

    private String clientId1;
    private String registrationAccessToken1;
    private String registrationClientUri1;

    @Parameters({"redirectUris", "sectorIdentifierUri"})
    @Test
    public void requestClientAssociate1(final String redirectUris, final String sectorIdentifierUri) throws Exception {
        showTitle("requestClientAssociate1");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());
    }

    @Parameters({"redirectUris", "sectorIdentifierUri", "logoutUri"})
    @Test
    public void requestClientAssociate2(final String redirectUris, final String sectorIdentifierUri,
                                        final String logoutUri) throws Exception {
        showTitle("requestClientAssociate2");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setContacts(Arrays.asList("javier@gluu.org", "javier.rojas.blum@gmail.com"));
        registerRequest.setScopes(Arrays.asList("openid", "address", "profile", "email", "phone", "clientinfo", "invalid_scope"));
        registerRequest.setLogoUri("http://www.gluu.org/wp-content/themes/gluursn/images/logo.png");
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_JWT);
        registerRequest.setPolicyUri("http://www.gluu.org/policy");
        registerRequest.setJwksUri("http://www.gluu.org/jwks");
        registerRequest.setSectorIdentifierUri(sectorIdentifierUri);
        registerRequest.setSubjectType(SubjectType.PAIRWISE);
        registerRequest.setRequestUris(Arrays.asList("http://www.gluu.org/request"));
        registerRequest.setLogoutUris(Lists.newArrayList(logoutUri));
        registerRequest.setLogoutSessionRequired(true);
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.RS512);
        registerRequest.setIdTokenEncryptedResponseAlg(KeyEncryptionAlgorithm.RSA1_5);
        registerRequest.setIdTokenEncryptedResponseEnc(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256);
        registerRequest.setUserInfoSignedResponseAlg(SignatureAlgorithm.RS384);
        registerRequest.setUserInfoEncryptedResponseAlg(KeyEncryptionAlgorithm.A128KW);
        registerRequest.setUserInfoEncryptedResponseEnc(BlockEncryptionAlgorithm.A128GCM);
        registerRequest.setRequestObjectSigningAlg(SignatureAlgorithm.RS256);
        registerRequest.setRequestObjectEncryptionAlg(KeyEncryptionAlgorithm.A256KW);
        registerRequest.setRequestObjectEncryptionEnc(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512);
        registerRequest.setTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_JWT);
        registerRequest.setTokenEndpointAuthSigningAlg(SignatureAlgorithm.ES256);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        registerClient.setExecutor(clientExecutor(true));
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());
        assertNotNull(response.getClaims().get(SCOPES.toString()));
        assertNotNull(response.getClaims().get(LOGOUT_SESSION_REQUIRED.toString()));
        assertTrue(Boolean.parseBoolean(response.getClaims().get(LOGOUT_SESSION_REQUIRED.toString())));
        assertNotNull(response.getClaims().get(LOGOUT_URI.toString()));
        assertTrue(new JSONArray(response.getClaims().get(LOGOUT_URI.toString())).getString(0).equals(logoutUri));
        assertNotNull(response.getClaims().get(ID_TOKEN_SIGNED_RESPONSE_ALG.toString()));
        assertEquals(SignatureAlgorithm.RS512,
                SignatureAlgorithm.fromString(response.getClaims().get(ID_TOKEN_SIGNED_RESPONSE_ALG.toString())));
        assertNotNull(response.getClaims().get(ID_TOKEN_ENCRYPTED_RESPONSE_ALG.toString()));
        assertEquals(KeyEncryptionAlgorithm.RSA1_5,
                KeyEncryptionAlgorithm.fromName(response.getClaims().get(ID_TOKEN_ENCRYPTED_RESPONSE_ALG.toString())));
        assertNotNull(response.getClaims().get(ID_TOKEN_ENCRYPTED_RESPONSE_ENC.toString()));
        assertEquals(BlockEncryptionAlgorithm.A128CBC_PLUS_HS256,
                BlockEncryptionAlgorithm.fromName(response.getClaims().get(ID_TOKEN_ENCRYPTED_RESPONSE_ENC.toString())));
        assertNotNull(response.getClaims().get(USERINFO_SIGNED_RESPONSE_ALG.toString()));
        assertEquals(SignatureAlgorithm.RS384,
                SignatureAlgorithm.fromString(response.getClaims().get(USERINFO_SIGNED_RESPONSE_ALG.toString())));
        assertNotNull(response.getClaims().get(USERINFO_ENCRYPTED_RESPONSE_ALG.toString()));
        assertEquals(KeyEncryptionAlgorithm.A128KW,
                KeyEncryptionAlgorithm.fromName(response.getClaims().get(USERINFO_ENCRYPTED_RESPONSE_ALG.toString())));
        assertNotNull(response.getClaims().get(USERINFO_ENCRYPTED_RESPONSE_ENC.toString()));
        assertEquals(BlockEncryptionAlgorithm.A128GCM,
                BlockEncryptionAlgorithm.fromName(response.getClaims().get(USERINFO_ENCRYPTED_RESPONSE_ENC.toString())));
        assertNotNull(response.getClaims().get(REQUEST_OBJECT_SIGNING_ALG.toString()));
        assertEquals(SignatureAlgorithm.RS256,
                SignatureAlgorithm.fromString(response.getClaims().get(REQUEST_OBJECT_SIGNING_ALG.toString())));
        assertNotNull(response.getClaims().get(REQUEST_OBJECT_ENCRYPTION_ALG.toString()));
        assertEquals(KeyEncryptionAlgorithm.A256KW,
                KeyEncryptionAlgorithm.fromName(response.getClaims().get(REQUEST_OBJECT_ENCRYPTION_ALG.toString())));
        assertNotNull(response.getClaims().get(REQUEST_OBJECT_ENCRYPTION_ENC.toString()));
        assertEquals(BlockEncryptionAlgorithm.A256CBC_PLUS_HS512,
                BlockEncryptionAlgorithm.fromName(response.getClaims().get(REQUEST_OBJECT_ENCRYPTION_ENC.toString())));
        assertNotNull(response.getClaims().get(TOKEN_ENDPOINT_AUTH_METHOD.toString()));
        assertEquals(AuthenticationMethod.CLIENT_SECRET_JWT,
                AuthenticationMethod.fromString(response.getClaims().get(TOKEN_ENDPOINT_AUTH_METHOD.toString())));
        assertNotNull(response.getClaims().get(TOKEN_ENDPOINT_AUTH_SIGNING_ALG.toString()));
        assertEquals(SignatureAlgorithm.ES256,
                SignatureAlgorithm.fromString(response.getClaims().get(TOKEN_ENDPOINT_AUTH_SIGNING_ALG.toString())));
        JSONArray scopesJsonArray = new JSONArray(response.getClaims().get(SCOPES.toString()));
        List<String> scopes = new ArrayList<String>();
        for (int i = 0; i < scopesJsonArray.length(); i++) {
            scopes.add(scopesJsonArray.get(i).toString());
        }
        assertTrue(scopes.contains("openid"));
        assertTrue(scopes.contains("address"));
        assertTrue(scopes.contains("email"));
        assertTrue(scopes.contains("profile"));
        assertTrue(scopes.contains("phone"));
        assertTrue(scopes.contains("clientinfo"));

        clientId1 = response.getClientId();
        registrationAccessToken1 = response.getRegistrationAccessToken();
        registrationClientUri1 = response.getRegistrationClientUri();
    }

    @Test(dependsOnMethods = "requestClientAssociate2")
    public void requestClientUpdate() throws Exception {
        showTitle("requestClientUpdate");

        final String logoUriNewValue = "http://www.gluu.org/test/yuriy/logo.png";
        final String contact1NewValue = "yuriy@gluu.org";
        final String contact2NewValue = "yuriyz@gmail.com";

        Calendar clientSecretExpiresAtCalendar = Calendar.getInstance();
        clientSecretExpiresAtCalendar.add(Calendar.DAY_OF_YEAR, 1);
        Date clientSecretExpiresAt = clientSecretExpiresAtCalendar.getTime();

        final RegisterRequest registerRequest = new RegisterRequest(registrationAccessToken1);
        registerRequest.setHttpMethod(HttpMethod.PUT);
        registerRequest.setContacts(Arrays.asList(contact1NewValue, contact2NewValue));
        registerRequest.setLogoUri(logoUriNewValue);

        registerRequest.setClientSecretExpiresAt(clientSecretExpiresAt);

        final RegisterClient registerClient = new RegisterClient(registrationClientUri1);
        registerClient.setRequest(registerRequest);
        registerClient.setExecutor(clientExecutor(true));
        final RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());

        // check whether info is really updated
        final String responseContacts = response.getClaims().get(CONTACTS.toString());
        final String responseLogoUri = response.getClaims().get(LOGO_URI.toString());

        assertTrue(responseContacts.contains(contact1NewValue) && responseContacts.contains(contact2NewValue));
        assertNotNull(responseLogoUri.equals(logoUriNewValue));

        long diff = response.getClientSecretExpiresAt().getTime() / 10000 - clientSecretExpiresAt.getTime() / 10000; // check after division on 1000 because of internal server conversion
        System.out.println("Diff: " + diff + ", respTime: " + response.getClientSecretExpiresAt().getTime() + ", expAt: " + clientSecretExpiresAt.getTime());
        assertTrue(Math.abs(diff) == 0);
    }

    @Test(dependsOnMethods = "requestClientAssociate2")
    public void requestClientRead() throws Exception {
        showTitle("requestClientRead");

        RegisterRequest registerRequest = new RegisterRequest(registrationAccessToken1);

        RegisterClient registerClient = new RegisterClient(registrationClientUri1);
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getRegistrationClientUri());
        assertNotNull(response.getClientSecretExpiresAt());
        assertNotNull(response.getClaims().get(APPLICATION_TYPE.toString()));
        assertNotNull(response.getClaims().get(POLICY_URI.toString()));
        assertNotNull(response.getClaims().get(REQUEST_OBJECT_SIGNING_ALG.toString()));
        assertNotNull(response.getClaims().get(CONTACTS.toString()));
        assertNotNull(response.getClaims().get(SECTOR_IDENTIFIER_URI.toString()));
        assertNotNull(response.getClaims().get(SUBJECT_TYPE.toString()));
        assertNotNull(response.getClaims().get(ID_TOKEN_SIGNED_RESPONSE_ALG.toString()));
        assertNotNull(response.getClaims().get(JWKS_URI.toString()));
        assertNotNull(response.getClaims().get(CLIENT_NAME.toString()));
        assertNotNull(response.getClaims().get(LOGO_URI.toString()));
        assertNotNull(response.getClaims().get(REQUEST_URIS.toString()));
        assertNotNull(response.getClaims().get("scopes"));
    }

    @Parameters({"redirectUris", "sectorIdentifierUri"})
    @Test
    // ATTENTION : uncomment test annotation only if 112-customAttributes.ldif (located in server test resources)
    // is loaded by ldap server.
    public void requestClientRegistrationWithCustomAttributes(
            final String redirectUris, final String sectorIdentifierUri) throws Exception {
        showTitle("requestClientRegistrationWithCustomAttributes");

        final RegisterRequest request = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));

        // custom attribute must be declared in oxauth-config.xml in dynamic-registration-custom-attribute tag
        request.addCustomAttribute("myCustomAttr1", "customAttrValue1");
        request.addCustomAttribute("myCustomAttr2", "customAttrValue2");
        request.setSectorIdentifierUri(sectorIdentifierUri);

        final RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(request);
        final RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());
    }

    @Test
    public void requestClientRegistrationFail1() throws Exception {
        showTitle("requestClientRegistrationFail1");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        RegisterResponse response = registerClient.execRegister(null, null, null);

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Test
    public void requestClientRegistrationFail2() throws Exception {
        showTitle("requestClientRegistrationFail2");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        RegisterResponse response = registerClient.execRegister(ApplicationType.WEB, "oxAuth test app", null); // Missing redirect URIs

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Test
    public void requestClientRegistrationFail3() throws Exception {
        showTitle("requestClientRegistrationFail3");

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        RegisterResponse response = registerClient.execRegister(ApplicationType.WEB, "oxAuth test app",
                Arrays.asList("https://client.example.com/cb#fail_fragment"));

        showClient(registerClient);
        assertEquals(response.getStatus(), 400, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getEntity(), "The entity is null");
        assertNotNull(response.getErrorType(), "The error type is null");
        assertNotNull(response.getErrorDescription(), "The error description is null");
    }

    @Parameters({"redirectUris"})
    @Test
    public void requestClientRegistrationFail4(final String redirectUris) throws Exception {
        showTitle("requestClientRegistrationFail4");

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.WEB, "oxAuth test app",
                StringUtils.spaceSeparatedToList(redirectUris));
        registerRequest.setIdTokenSignedResponseAlg(SignatureAlgorithm.NONE); // id_token signature cannot be none

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setRequest(registerRequest);
        registerClient.setExecutor(clientExecutor(true));
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 400);
        assertNotNull(response.getEntity());
        assertNotNull(response.getErrorType());
        assertNotNull(response.getErrorDescription());
    }

    @Parameters({"redirectUris"})
    @Test
    public void registerWithCustomURI(final String redirectUris) throws Exception {
        showTitle("requestClientAssociate1");

        List<String> redirectUriList = Lists.newArrayList(StringUtils.spaceSeparatedToList(redirectUris));
        redirectUriList.add("myschema://client.example.com/cb"); // URI with custom schema

        RegisterRequest registerRequest = new RegisterRequest(ApplicationType.NATIVE, "oxAuth native test app with custom schema in URI",
                redirectUriList);
        registerRequest.setSubjectType(SubjectType.PUBLIC);

        RegisterClient registerClient = new RegisterClient(registrationEndpoint);
        registerClient.setExecutor(clientExecutor(true));
        registerClient.setRequest(registerRequest);
        RegisterResponse response = registerClient.exec();

        showClient(registerClient);
        assertEquals(response.getStatus(), 200, "Unexpected response code: " + response.getEntity());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientSecretExpiresAt());
    }
}