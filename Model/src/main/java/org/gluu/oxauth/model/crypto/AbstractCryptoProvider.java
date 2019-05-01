/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */
package org.gluu.oxauth.model.crypto;

import org.apache.log4j.Logger;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.crypto.signature.ECEllipticCurve;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.oxeleven.model.JwksRequestParam;
import org.gluu.oxeleven.model.KeyRequestParam;

import sun.security.rsa.RSAPublicKeyImpl;

import static org.gluu.oxauth.model.jwk.JWKParameter.*;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

/**
 * @author Javier Rojas Blum
 * @version February 12, 2019
 */
public abstract class AbstractCryptoProvider {

    protected static final Logger LOG = Logger.getLogger(AbstractCryptoProvider.class);

    public abstract JSONObject generateKey(Algorithm algorithm, Long expirationTime) throws Exception;

    public abstract String sign(String signingInput, String keyId, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception;

    public abstract boolean verifySignature(String signingInput, String encodedSignature, String keyId, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception;

    public abstract boolean deleteKey(String keyId) throws Exception;

    public String getKeyId(JSONWebKeySet jsonWebKeySet, Algorithm algorithm, Use use) throws Exception {
        for (JSONWebKey key : jsonWebKeySet.getKeys()) {
            if (algorithm == key.getAlg() && (use == null || use == key.getUse())) {
                return key.getKid();
            }
        }

        return null;
    }

    public JwksRequestParam getJwksRequestParam(JSONObject jwkJsonObject) throws JSONException {
        JwksRequestParam jwks = new JwksRequestParam();
        jwks.setKeyRequestParams(new ArrayList<KeyRequestParam>());

        KeyRequestParam key = new KeyRequestParam();
        key.setAlg(jwkJsonObject.getString(ALGORITHM));
        key.setKid(jwkJsonObject.getString(KEY_ID));
        key.setUse(jwkJsonObject.getString(KEY_USE));
        key.setKty(jwkJsonObject.getString(KEY_TYPE));

        key.setN(jwkJsonObject.optString(MODULUS));
        key.setE(jwkJsonObject.optString(EXPONENT));

        key.setCrv(jwkJsonObject.optString(CURVE));
        key.setX(jwkJsonObject.optString(X));
        key.setY(jwkJsonObject.optString(Y));

        jwks.getKeyRequestParams().add(key);

        return jwks;
    }

    public static JSONObject generateJwks(int keyRegenerationInterval, int idTokenLifeTime, AppConfiguration configuration) throws Exception {
        JSONArray keys = new JSONArray();

        GregorianCalendar expirationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        expirationTime.add(GregorianCalendar.HOUR, keyRegenerationInterval);
        expirationTime.add(GregorianCalendar.SECOND, idTokenLifeTime);

        AbstractCryptoProvider cryptoProvider = CryptoProviderFactory.getCryptoProvider(configuration);

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.RS256, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.RS384, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.RS512, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.ES256, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.ES384, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.ES512, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.PS256, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.PS384, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.PS512, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.RSA1_5, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        try {
            keys.put(cryptoProvider.generateKey(Algorithm.RSA_OAEP, expirationTime.getTimeInMillis()));
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
        }

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(JSON_WEB_KEY_SET, keys);

        return jsonObject;
    }

    public PublicKey getPublicKey(String alias, JSONObject jwks) throws Exception {
        java.security.PublicKey publicKey = null;

        JSONArray webKeys = jwks.getJSONArray(JSON_WEB_KEY_SET);
        for (int i = 0; i < webKeys.length(); i++) {
            JSONObject key = webKeys.getJSONObject(i);
            if (alias.equals(key.getString(KEY_ID))) {
                AlgorithmFamily family = null;
                if (key.has(ALGORITHM)) {
                    Algorithm algorithm = Algorithm.fromString(key.optString(ALGORITHM));
                    family = algorithm.getFamily();
                } else if (key.has(KEY_TYPE)) {
                    family = AlgorithmFamily.fromString(key.getString(KEY_TYPE));
                }

                if (AlgorithmFamily.RSA.equals(family)) {
                    publicKey = new RSAPublicKeyImpl(
                            new BigInteger(1, Base64Util.base64urldecode(key.getString(MODULUS))),
                            new BigInteger(1, Base64Util.base64urldecode(key.getString(EXPONENT))));
                } else if (AlgorithmFamily.EC.equals(family)) {
                    ECEllipticCurve curve = ECEllipticCurve.fromString(key.optString(CURVE));
                    AlgorithmParameters parameters = AlgorithmParameters.getInstance(AlgorithmFamily.EC.toString());
                    parameters.init(new ECGenParameterSpec(curve.getAlias()));
                    ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

                    publicKey = KeyFactory.getInstance(AlgorithmFamily.EC.toString()).generatePublic(new ECPublicKeySpec(
                            new ECPoint(
                                    new BigInteger(1, Base64Util.base64urldecode(key.getString(X))),
                                    new BigInteger(1, Base64Util.base64urldecode(key.getString(Y)))
                            ), ecParameters));
                }

                if (key.has(EXPIRATION_TIME)) {
                    checkKeyExpiration(alias, key.getLong(EXPIRATION_TIME));
                }
            }
        }

        return publicKey;
    }

    protected void checkKeyExpiration(String alias, Long expirationTime) {
        try {
            Date expirationDate = new Date(expirationTime);
            SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            Date today = new Date();
            long DateDiff = expirationTime - today.getTime();
            long expiresIn = DateDiff / (24 * 60 * 60 * 1000);
            if (expiresIn <= 0) {
                LOG.warn("\nWARNING! Expired Key with alias: " + alias
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
            } else if (expiresIn <= 100) {
                LOG.warn("\nWARNING! Key with alias: " + alias
                        + "\n\tExpires In: " + expiresIn + " days"
                        + "\n\tExpires On: " + ft.format(expirationDate)
                        + "\n\tToday's Date: " + ft.format(today));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}