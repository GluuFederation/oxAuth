/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.crypto;

import org.apache.http.HttpStatus;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.oxeleven.client.*;
import org.gluu.oxeleven.model.JwksRequestParam;
import org.gluu.oxeleven.model.KeyRequestParam;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.ArrayList;

import static org.gluu.oxauth.model.jwk.JWKParameter.*;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public class OxElevenCryptoProvider extends AbstractCryptoProvider {

    private String generateKeyEndpoint;
    private String signEndpoint;
    private String verifySignatureEndpoint;
    private String deleteKeyEndpoint;
    private String accessToken;

    public OxElevenCryptoProvider(String generateKeyEndpoint, String signEndpoint, String verifySignatureEndpoint,
                                  String deleteKeyEndpoint, String accessToken) {
        this.generateKeyEndpoint = generateKeyEndpoint;
        this.signEndpoint = signEndpoint;
        this.verifySignatureEndpoint = verifySignatureEndpoint;
        this.deleteKeyEndpoint = deleteKeyEndpoint;
        this.accessToken = accessToken;
    }

    @Override
    public boolean containsKey(String keyId) {
        return false;
    }

    @Override
    public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception {
        return generateKey(algorithm, expirationTime, use, 2048);
    }

    @Override
    public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use, int keyLength) throws Exception {
        GenerateKeyRequest request = new GenerateKeyRequest();
        request.setSignatureAlgorithm(algorithm.toString());
        request.setExpirationTime(expirationTime);
        request.setAccessToken(accessToken);

        GenerateKeyClient client = new GenerateKeyClient(generateKeyEndpoint);
        client.setRequest(request);

        GenerateKeyResponse response = client.exec();
        if (response.getStatus() == HttpStatus.SC_OK && response.getKeyId() != null) {
            return response.getJSONEntity();
        } else {
            throw new Exception(response.getEntity());
        }
    }

    @Override
    public String sign(String signingInput, String keyId, String shardSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        SignRequest request = new SignRequest();
        request.getSignRequestParam().setSigningInput(signingInput);
        request.getSignRequestParam().setAlias(keyId);
        request.getSignRequestParam().setSharedSecret(shardSecret);
        request.getSignRequestParam().setSignatureAlgorithm(signatureAlgorithm.getName());
        request.setAccessToken(accessToken);

        SignClient client = new SignClient(signEndpoint);
        client.setRequest(request);

        SignResponse response = client.exec();
        if (response.getStatus() == HttpStatus.SC_OK && response.getSignature() != null) {
            return response.getSignature();
        } else {
            throw new Exception(response.getEntity());
        }
    }

    @Override
    public boolean verifySignature(String signingInput, String encodedSignature, String keyId, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        VerifySignatureRequest request = new VerifySignatureRequest();
        request.getVerifySignatureRequestParam().setSigningInput(signingInput);
        request.getVerifySignatureRequestParam().setSignature(encodedSignature);
        request.getVerifySignatureRequestParam().setAlias(keyId);
        request.getVerifySignatureRequestParam().setSharedSecret(sharedSecret);
        request.getVerifySignatureRequestParam().setSignatureAlgorithm(signatureAlgorithm.getName());
        request.setAccessToken(accessToken);
        if (jwks != null) {
            request.getVerifySignatureRequestParam().setJwksRequestParam(getJwksRequestParam(jwks));
        }

        VerifySignatureClient client = new VerifySignatureClient(verifySignatureEndpoint);
        client.setRequest(request);

        VerifySignatureResponse response = client.exec();
        if (response.getStatus() == HttpStatus.SC_OK) {
            return response.isVerified();
        } else {
            throw new SignatureException(response.getEntity());
        }
    }

    private static JwksRequestParam getJwksRequestParam(JSONObject jwksJsonObject) throws JSONException {
        JwksRequestParam jwks = new JwksRequestParam();
        jwks.setKeyRequestParams(new ArrayList<>());

        JSONArray keys = jwksJsonObject.getJSONArray(JSON_WEB_KEY_SET);
        for (int i = 0; i < keys.length(); i++) {
            jwks.getKeyRequestParams().add(mapToKeyRequestParam(keys.getJSONObject(i)));
        }

        return jwks;
    }

    private static KeyRequestParam mapToKeyRequestParam(JSONObject jwk) {
        KeyRequestParam key = new KeyRequestParam();
        key.setAlg(jwk.getString(ALGORITHM));
        key.setKid(jwk.getString(KEY_ID));
        key.setUse(jwk.getString(KEY_USE));
        key.setKty(jwk.getString(KEY_TYPE));

        key.setN(jwk.optString(MODULUS));
        key.setE(jwk.optString(EXPONENT));

        key.setCrv(jwk.optString(CURVE));
        key.setX(jwk.optString(X));
        key.setY(jwk.optString(Y));
        return key;
    }

    @Override
    public boolean deleteKey(String keyId) throws Exception {
        DeleteKeyRequest request = new DeleteKeyRequest();
        request.setAlias(keyId);
        request.setAccessToken(accessToken);

        DeleteKeyClient client = new DeleteKeyClient(deleteKeyEndpoint);
        client.setRequest(request);

        DeleteKeyResponse response = client.exec();
        if (response.getStatus() == org.apache.http.HttpStatus.SC_OK) {
            return response.isDeleted();
        } else {
            throw new Exception(response.getEntity());
        }
    }

	@Override
	public PrivateKey getPrivateKey(String keyId) {
        throw new UnsupportedOperationException("Method not implemented.");
	}
}