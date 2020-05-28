/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.authorize;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.common.Display;
import org.gluu.oxauth.model.common.Prompt;
import org.gluu.oxauth.model.common.ResponseType;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.crypto.encryption.BlockEncryptionAlgorithm;
import org.gluu.oxauth.model.crypto.encryption.KeyEncryptionAlgorithm;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.exception.InvalidJweException;
import org.gluu.oxauth.model.exception.InvalidJwtException;
import org.gluu.oxauth.model.jwe.Jwe;
import org.gluu.oxauth.model.jwe.JweDecrypterImpl;
import org.gluu.oxauth.model.jwt.JwtHeader;
import org.gluu.oxauth.model.jwt.JwtHeaderName;
import org.gluu.oxauth.model.registration.Client;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.oxauth.model.util.JwtUtil;
import org.gluu.oxauth.model.util.Util;
import org.gluu.oxauth.service.ClientService;
import org.gluu.service.cdi.util.CdiUtil;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Javier Rojas Blum
 * @version November 20, 2018
 */
public class JwtAuthorizationRequest {

    // Header
    private String type;
    private String algorithm;
    private String encryptionAlgorithm;
    private String keyId;

    // Payload
    private List<ResponseType> responseTypes;
    private String clientId;
    private List<String> scopes;
    private String redirectUri;
    private String nonce;
    private String state;
    private List<String> aud = Lists.newArrayList();
    private Display display;
    private List<Prompt> prompts;
    private UserInfoMember userInfoMember;
    private IdTokenMember idTokenMember;
    private Integer exp;

    private String encodedJwt;
    private String payload;

    private AppConfiguration appConfiguration;

    public JwtAuthorizationRequest(AppConfiguration appConfiguration, AbstractCryptoProvider cryptoProvider, String encodedJwt, Client client) throws InvalidJwtException, InvalidJweException {
        try {
            this.appConfiguration = appConfiguration;
            this.responseTypes = new ArrayList<ResponseType>();
            this.scopes = new ArrayList<String>();
            this.prompts = new ArrayList<Prompt>();
            this.encodedJwt = encodedJwt;

            if (StringUtils.isEmpty(encodedJwt)) {
                throw new InvalidJwtException("The JWT is null or empty");
            }


            String[] parts = encodedJwt.split("\\.");

            if (parts.length == 5) {
                String encodedHeader = parts[0];

                JwtHeader jwtHeader = new JwtHeader(encodedHeader);

                keyId = jwtHeader.getKeyId();
                KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.fromName(
                        jwtHeader.getClaimAsString(JwtHeaderName.ALGORITHM));
                BlockEncryptionAlgorithm blockEncryptionAlgorithm = BlockEncryptionAlgorithm.fromName(
                        jwtHeader.getClaimAsString(JwtHeaderName.ENCRYPTION_METHOD));

                JweDecrypterImpl jweDecrypter = null;
                if ("RSA".equals(keyEncryptionAlgorithm.getFamily())) {
                    PrivateKey privateKey = cryptoProvider.getPrivateKey(keyId);
                    jweDecrypter = new JweDecrypterImpl(privateKey);
                } else {
                    ClientService clientService = CdiUtil.bean(ClientService.class);
                    jweDecrypter = new JweDecrypterImpl(clientService.decryptSecret(client.getClientSecret()).getBytes(StandardCharsets.UTF_8));
                }
                jweDecrypter.setKeyEncryptionAlgorithm(keyEncryptionAlgorithm);
                jweDecrypter.setBlockEncryptionAlgorithm(blockEncryptionAlgorithm);

                Jwe jwe = jweDecrypter.decrypt(encodedJwt);

                loadHeader(jwe.getHeader().toJsonString());
                loadPayload(jwe.getClaims().toJsonString());
            } else if (parts.length == 2 || parts.length == 3) {
                String encodedHeader = parts[0];
                String encodedClaim = parts[1];
                String encodedSignature = StringUtils.EMPTY;
                if (parts.length == 3) {
                    encodedSignature = parts[2];
                }

                String signingInput = encodedHeader + "." + encodedClaim;
                String header = new String(Base64Util.base64urldecode(encodedHeader), StandardCharsets.UTF_8);
                String payload = new String(Base64Util.base64urldecode(encodedClaim), StandardCharsets.UTF_8);
                payload = payload.replace("\\", "");

                loadHeader(header);

                SignatureAlgorithm sigAlg = SignatureAlgorithm.fromString(algorithm);
                if (sigAlg == null) {
                    throw new InvalidJwtException("The JWT algorithm is not supported");
                }
                if (sigAlg == SignatureAlgorithm.NONE && appConfiguration.getFapiCompatibility()) {
                    throw new InvalidJwtException("None algorithm is not allowed for FAPI");
                }
                if (!validateSignature(cryptoProvider, sigAlg, client, signingInput, encodedSignature)) {
                    throw new InvalidJwtException("The JWT signature is not valid");
                }

                loadPayload(payload);
            } else {
                throw new InvalidJwtException("The JWT is not well formed");
            }

        } catch (Exception e) {
            throw new InvalidJwtException(e);
        }
    }

    public String getEncodedJwt() {
        return encodedJwt;
    }

    private void loadHeader(String header) throws JSONException {
        JSONObject jsonHeader = new JSONObject(header);

        if (jsonHeader.has("typ")) {
            type = jsonHeader.getString("typ");
        }
        if (jsonHeader.has("alg")) {
            algorithm = jsonHeader.getString("alg");
        }
        if (jsonHeader.has("enc")) {
            encryptionAlgorithm = jsonHeader.getString("enc");
        }
        if (jsonHeader.has("kid")) {
            keyId = jsonHeader.getString("kid");
        }
    }

    private void loadPayload(String payload) throws JSONException, UnsupportedEncodingException {
        JSONObject jsonPayload = new JSONObject(payload);

        if (jsonPayload.has("response_type")) {
            JSONArray responseTypeJsonArray = jsonPayload.optJSONArray("response_type");
            if (responseTypeJsonArray != null) {
                for (int i = 0; i < responseTypeJsonArray.length(); i++) {
                    ResponseType responseType = ResponseType.fromString(responseTypeJsonArray.getString(i));
                    responseTypes.add(responseType);
                }
            } else {
                responseTypes.addAll(ResponseType.fromString(jsonPayload.getString("response_type"), " "));
            }
        }
        if (jsonPayload.has("exp")) {
            exp = jsonPayload.getInt("exp");
        }
        if (jsonPayload.has("aud")) {
            final String audStr = jsonPayload.optString("aud");
            if (StringUtils.isNotBlank(audStr)) {
                this.aud.add(audStr);
            }
            final JSONArray audArray = jsonPayload.optJSONArray("aud");
            if (audArray != null && audArray.length() > 0) {
                this.aud.addAll(Util.asList(audArray));
            }
        }
        if (jsonPayload.has("client_id")) {
            clientId = jsonPayload.getString("client_id");
        }
        if (jsonPayload.has("scope")) {
            JSONArray scopesJsonArray = jsonPayload.optJSONArray("scope");
            if (scopesJsonArray != null) {
                for (int i = 0; i < scopesJsonArray.length(); i++) {
                    String scope = scopesJsonArray.getString(i);
                    scopes.add(scope);
                }
            } else {
                String scopeStringList = jsonPayload.getString("scope");
                scopes.addAll(Util.splittedStringAsList(scopeStringList, " "));
            }
        }
        if (jsonPayload.has("redirect_uri")) {
            redirectUri = URLDecoder.decode(jsonPayload.getString("redirect_uri"), "UTF-8");
        }
        if (jsonPayload.has("nonce")) {
            nonce = jsonPayload.getString("nonce");
        }
        if (jsonPayload.has("state")) {
            state = jsonPayload.getString("state");
        }
        if (jsonPayload.has("display")) {
            display = Display.fromString(jsonPayload.getString("display"));
        }
        if (jsonPayload.has("prompt")) {
            JSONArray promptJsonArray = jsonPayload.optJSONArray("prompt");
            if (promptJsonArray != null) {
                for (int i = 0; i < promptJsonArray.length(); i++) {
                    Prompt prompt = Prompt.fromString(promptJsonArray.getString(i));
                    prompts.add(prompt);
                }
            } else {
                prompts.addAll(Prompt.fromString(jsonPayload.getString("prompt"), " "));
            }
        }
        if (jsonPayload.has("claims")) {
            JSONObject claimsJsonObject = jsonPayload.getJSONObject("claims");

            if (claimsJsonObject.has("userinfo")) {
                userInfoMember = new UserInfoMember(claimsJsonObject.getJSONObject("userinfo"));
            }
            if (claimsJsonObject.has("id_token")) {
                idTokenMember = new IdTokenMember(claimsJsonObject.getJSONObject("id_token"));
            }
        }
        this.payload = payload;
    }

    private boolean validateSignature(AbstractCryptoProvider cryptoProvider, SignatureAlgorithm signatureAlgorithm, Client client, String signingInput, String signature) throws Exception {
        ClientService clientService = CdiUtil.bean(ClientService.class);
        String sharedSecret = clientService.decryptSecret(client.getClientSecret());
        JSONObject jwks = Strings.isNullOrEmpty(client.getJwks()) ?
                JwtUtil.getJSONWebKeys(client.getJwksUri()) :
                new JSONObject(client.getJwks());
        return cryptoProvider.verifySignature(signingInput, signature, keyId, jwks, sharedSecret, signatureAlgorithm);
    }

    public String getKeyId() {
        return keyId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public List<ResponseType> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<ResponseType> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public Display getDisplay() {
        return display;
    }

    public void setDisplay(Display display) {
        this.display = display;
    }

    public List<Prompt> getPrompts() {
        return prompts;
    }

    public void setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
    }

    public UserInfoMember getUserInfoMember() {
        return userInfoMember;
    }

    public void setUserInfoMember(UserInfoMember userInfoMember) {
        this.userInfoMember = userInfoMember;
    }

    public IdTokenMember getIdTokenMember() {
        return idTokenMember;
    }

    public void setIdTokenMember(IdTokenMember idTokenMember) {
        this.idTokenMember = idTokenMember;
    }

    public Integer getExp() {
        return exp;
    }

    public List<String> getAud() {
        if (aud == null) aud = Lists.newArrayList();
        return aud;
    }

    public void setAud(List<String> aud) {
        this.aud = aud;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}