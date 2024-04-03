/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */
package org.gluu.oxauth.model.crypto;

import com.google.common.collect.Lists;
import org.apache.log4j.Logger;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.crypto.signature.ECEllipticCurve;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.oxauth.model.util.Base64Util;
import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.security.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.gluu.oxauth.model.jwk.JWKParameter.*;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public abstract class AbstractCryptoProvider {

    protected static final Logger LOG = Logger.getLogger(AbstractCryptoProvider.class);

    private int keyRegenerationIntervalInDays = -1;

    public JSONObject generateKey(Algorithm algorithm, Long expirationTime) throws Exception {
        return generateKey(algorithm, expirationTime, Use.SIGNATURE);
    }

    public abstract JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception;

    public abstract JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use, int keyLength) throws Exception;

    public abstract String sign(String signingInput, String keyId, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception;

    public abstract boolean verifySignature(String signingInput, String encodedSignature, String keyId, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception;

    public abstract boolean deleteKey(String keyId) throws Exception;

    public abstract boolean containsKey(String keyId);

    public List<String> getKeys() {
        return Lists.newArrayList();
    }

    public abstract PrivateKey getPrivateKey(String keyId) throws Exception;

    public String getKeyId(JSONWebKeySet jsonWebKeySet, Algorithm algorithm, Use use) throws Exception {
        if (algorithm == null || AlgorithmFamily.HMAC.equals(algorithm.getFamily())) {
            return null;
        }
        for (JSONWebKey key : jsonWebKeySet.getKeys()) {
            if (algorithm == key.getAlg() && (use == null || use == key.getUse())) {
                return key.getKid();
            }
        }

        return null;
    }

    public static JSONObject generateJwks(AbstractCryptoProvider cryptoProvider, AppConfiguration configuration) {
        GregorianCalendar expirationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        expirationTime.add(GregorianCalendar.HOUR, configuration.getKeyRegenerationInterval());
        expirationTime.add(GregorianCalendar.SECOND, configuration.getIdTokenLifetime());

        long expiration = expirationTime.getTimeInMillis();

        final List<String> allowedAlgs = configuration.getKeyAlgsAllowedForGeneration();
        JSONArray keys = new JSONArray();

        for (Algorithm alg : Algorithm.values()) {
            try {
                if (!allowedAlgs.isEmpty() && !allowedAlgs.contains(alg.getParamName())) {
                    LOG.debug("Key generation for " + alg + " is skipped because it's not allowed by keyAlgsAllowedForGeneration configuration property.");
                    continue;
                }
                keys.put(cryptoProvider.generateKey(alg, expiration, alg.getUse()));
            } catch (Exception ex) {
                LOG.error("Algorithm: " + alg + ex.getMessage(), ex);
            }
        }

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(JSON_WEB_KEY_SET, keys);

        return jsonObject;
    }

    public PublicKey getPublicKey(String alias, JSONObject jwks, Algorithm requestedAlgorithm) throws Exception {
        JSONArray webKeys = jwks.getJSONArray(JSON_WEB_KEY_SET);

        try {
            if (alias == null) {
                if (webKeys.length() == 1) {
                    JSONObject key = webKeys.getJSONObject(0);
                    return processKey(requestedAlgorithm, alias, key);
                } else {
                    return null;
                }
            }
            for (int i = 0; i < webKeys.length(); i++) {
                JSONObject key = webKeys.getJSONObject(i);
                if (alias.equals(key.getString(KEY_ID))) {
                    PublicKey publicKey = processKey(requestedAlgorithm, alias, key);
                    if (publicKey != null) {
                        return publicKey;
                    }
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException |
                 InvalidParameterException e) {
            throw new Exception(e);
        }

        return null;
    }

    private PublicKey processKey(Algorithm requestedAlgorithm, String alias, JSONObject key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException, InvalidParameterException {
        PublicKey publicKey = null;
        AlgorithmFamily algorithmFamily = null;

        if (key.has(ALGORITHM)) {
            Algorithm algorithm = Algorithm.fromString(key.optString(ALGORITHM));

            if (requestedAlgorithm != null && !requestedAlgorithm.equals(algorithm)) {
                LOG.trace("kid matched but algorithm does not match. kid algorithm:" + algorithm
                        + ", requestedAlgorithm:" + requestedAlgorithm + ", kid:" + alias);
                return null;
            }
            algorithmFamily = algorithm.getFamily();
        } else if (key.has(KEY_TYPE)) {
            algorithmFamily = AlgorithmFamily.fromString(key.getString(KEY_TYPE));
        } else {
            throw new InvalidParameterException("Wrong key (JSONObject): doesn't contain 'alg' and 'kty' properties");
        }

        switch (algorithmFamily) {
            case RSA: {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                        new BigInteger(1, Base64Util.base64urldecode(key.getString(MODULUS))),
                        new BigInteger(1, Base64Util.base64urldecode(key.getString(EXPONENT))));
                publicKey = keyFactory.generatePublic(pubKeySpec);
                break;
            }
            case EC: {
                ECEllipticCurve curve = ECEllipticCurve.fromString(key.optString(CURVE));
                AlgorithmParameters parameters = AlgorithmParameters.getInstance(AlgorithmFamily.EC.toString());
                parameters.init(new ECGenParameterSpec(curve.getAlias()));
                ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
                publicKey = KeyFactory.getInstance(AlgorithmFamily.EC.toString())
                        .generatePublic(new ECPublicKeySpec(
                                new ECPoint(
                                        new BigInteger(1, Base64Util.base64urldecode(key.getString(X))),
                                        new BigInteger(1, Base64Util.base64urldecode(key.getString(Y)))),
                                ecParameters));
                break;
            }
            default: {
                throw new InvalidParameterException(String.format("Wrong AlgorithmFamily value: %s", algorithmFamily));
            }
        }

        if (key.has(EXPIRATION_TIME)) {
            checkKeyExpiration(alias, key.getLong(EXPIRATION_TIME));
        }

        return publicKey;
    }

    protected void checkKeyExpiration(String alias, Long expirationTime) {
        try {
            Date expirationDate = new Date(expirationTime);
            SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            Date today = new Date();
            long expiresInDays = (expirationTime - today.getTime()) / (24 * 60 * 60 * 1000);
            if (expiresInDays == 0) {
                LOG.warn("\nWARNING! Key will expire soon, alias: " + alias
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
                return;
            }
            if (expiresInDays < 0) {
                LOG.warn("\nWARNING! Expired Key is used, alias: " + alias
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
                return;
            }

            // re-generation interval is unknown, therefore we default to 30 days period warning
            if (keyRegenerationIntervalInDays <= 0 && expiresInDays < 30) {
                LOG.warn("\nWARNING! Key with alias: " + alias
                        + "\n\tExpires In: " + expiresInDays + " days"
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
                return;
            }

            if (expiresInDays < keyRegenerationIntervalInDays) {
                LOG.warn("\nWARNING! Key with alias: " + alias
                        + "\n\tExpires In: " + expiresInDays + " days"
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tKey Regeneration In: " + keyRegenerationIntervalInDays + " days"
                        + "\n\tToday's Date: " + ft.format(today));
            }
        } catch (Exception e) {
            LOG.error("Failed to check key expiration.", e);
        }
    }

    public int getKeyRegenerationIntervalInDays() {
        return keyRegenerationIntervalInDays;
    }

    public void setKeyRegenerationIntervalInDays(int keyRegenerationIntervalInDays) {
        this.keyRegenerationIntervalInDays = keyRegenerationIntervalInDays;
    }
}