/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.util;

import static org.gluu.oxauth.model.jwk.JWKParameter.ALGORITHM;
import static org.gluu.oxauth.model.jwk.JWKParameter.CERTIFICATE_CHAIN;
import static org.gluu.oxauth.model.jwk.JWKParameter.EXPONENT;
import static org.gluu.oxauth.model.jwk.JWKParameter.JSON_WEB_KEY_SET;
import static org.gluu.oxauth.model.jwk.JWKParameter.KEY_ID;
import static org.gluu.oxauth.model.jwk.JWKParameter.MODULUS;
import static org.gluu.oxauth.model.jwk.JWKParameter.PUBLIC_KEY;
import static org.gluu.oxauth.model.jwk.JWKParameter.X;
import static org.gluu.oxauth.model.jwk.JWKParameter.Y;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMParser;
import org.gluu.oxauth.model.crypto.Certificate;
import org.gluu.oxauth.model.crypto.PublicKey;
import org.gluu.oxauth.model.crypto.signature.ECDSAPublicKey;
import org.gluu.oxauth.model.crypto.signature.RSAPublicKey;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwt.Jwt;
import org.gluu.util.StringHelper;
import org.gluu.util.security.SecurityProviderUtility;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.json.JSONArray;
import org.json.JSONObject;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsonorg.JsonOrgModule;

/**
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version December 8, 2018
 */
public class JwtUtil {

    private static final Logger log = Logger.getLogger(JwtUtil.class);

    public static void printAlgorithmsAndProviders() {
        Set<String> algorithms = Security.getAlgorithms("Signature");
        for (String algorithm : algorithms) {
            log.trace("Algorithm (Signature): " + algorithm);
        }
        algorithms = Security.getAlgorithms("MessageDigest");
        for (String algorithm : algorithms) {
            log.trace("Algorithm (MessageDigest): " + algorithm);
        }
        algorithms = Security.getAlgorithms("Cipher");
        for (String algorithm : algorithms) {
            log.trace("Algorithm (Cipher): " + algorithm);
        }
        algorithms = Security.getAlgorithms("Mac");
        for (String algorithm : algorithms) {
            log.trace("Algorithm (Mac): " + algorithm);
        }
        algorithms = Security.getAlgorithms("KeyStore");
        for (String algorithm : algorithms) {
            log.trace("Algorithm (KeyStore): " + algorithm);
        }
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            log.trace("Provider: " + provider.getName());
        }
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] getMessageDigestSHA256(String data)
            throws NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest mda = MessageDigest.getInstance("SHA-256", SecurityProviderUtility.getBCProvider());
        return mda.digest(data.getBytes(Util.UTF8_STRING_ENCODING));
    }

    public static byte[] getMessageDigestSHA384(String data)
            throws NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest mda = MessageDigest.getInstance("SHA-384",SecurityProviderUtility.getBCProvider());
        return mda.digest(data.getBytes(Util.UTF8_STRING_ENCODING));
    }

    public static byte[] getMessageDigestSHA512(String data)
            throws NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest mda = MessageDigest.getInstance("SHA-512", SecurityProviderUtility.getBCProvider());
        return mda.digest(data.getBytes(Util.UTF8_STRING_ENCODING));
    }

    public static PublicKey getPublicKey(
            String jwksUri, String jwks, SignatureAlgorithm signatureAlgorithm, String keyId) {
        log.debug("Retrieving JWK...");

        JSONObject jsonKeyValue = getJsonKey(jwksUri, jwks, keyId);

        if (jsonKeyValue == null) {
            return null;
        }

        org.gluu.oxauth.model.crypto.PublicKey publicKey = null;

        try {
            String resultKeyId = jsonKeyValue.getString(KEY_ID);
            if (signatureAlgorithm == null) {
                signatureAlgorithm = SignatureAlgorithm.fromString(jsonKeyValue.getString(ALGORITHM));
                if (signatureAlgorithm == null) {
                    log.error(String.format("Failed to determine key '%s' signature algorithm", resultKeyId));
                    return null;
                }
            }

            JSONObject jsonPublicKey = jsonKeyValue;
            if (jsonKeyValue.has(PUBLIC_KEY)) {
                // Use internal jwks.json format
                jsonPublicKey = jsonKeyValue.getJSONObject(PUBLIC_KEY);
            }

            if (signatureAlgorithm == SignatureAlgorithm.RS256 || signatureAlgorithm == SignatureAlgorithm.RS384 || signatureAlgorithm == SignatureAlgorithm.RS512) {
                //String alg = jsonKeyValue.getString(ALGORITHM);
                //String use = jsonKeyValue.getString(KEY_USE);
                String exp = jsonPublicKey.getString(EXPONENT);
                String mod = jsonPublicKey.getString(MODULUS);

                BigInteger publicExponent = new BigInteger(1, Base64Util.base64urldecode(exp));
                BigInteger modulus = new BigInteger(1, Base64Util.base64urldecode(mod));

                publicKey = new RSAPublicKey(modulus, publicExponent);
            } else if (signatureAlgorithm == SignatureAlgorithm.ES256 || signatureAlgorithm == SignatureAlgorithm.ES384 || signatureAlgorithm == SignatureAlgorithm.ES512) {
                //String alg = jsonKeyValue.getString(ALGORITHM);
                //String use = jsonKeyValue.getString(KEY_USE);
                //String crv = jsonKeyValue.getString(CURVE);
                String xx = jsonPublicKey.getString(X);
                String yy = jsonPublicKey.getString(Y);

                BigInteger x = new BigInteger(1, Base64Util.base64urldecode(xx));
                BigInteger y = new BigInteger(1, Base64Util.base64urldecode(yy));

                publicKey = new ECDSAPublicKey(signatureAlgorithm, x, y);
            }

            if (publicKey != null && jsonKeyValue.has(CERTIFICATE_CHAIN)) {
                final String BEGIN = "-----BEGIN CERTIFICATE-----";
                final String END = "-----END CERTIFICATE-----";

                JSONArray certChain = jsonKeyValue.getJSONArray(CERTIFICATE_CHAIN);
                String certificateString = BEGIN + "\n" + certChain.getString(0) + "\n" + END;
                StringReader sr = new StringReader(certificateString);
                PEMParser pemReader = new PEMParser(sr);
                X509Certificate cert = (X509Certificate) pemReader.readObject();
                Certificate certificate = new Certificate(signatureAlgorithm, cert);
                publicKey.setCertificate(certificate);
            }
            if (publicKey != null) {
                publicKey.setKeyId(resultKeyId);
                publicKey.setSignatureAlgorithm(signatureAlgorithm);
            }
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }

        return publicKey;
    }

    public static JSONObject getJsonKey(String jwksUri, String jwks, String keyId) {
        log.debug("Retrieving JWK Key...");

        JSONObject jsonKey = null;
        try {
            if (StringHelper.isEmpty(jwks)) {
                javax.ws.rs.client.Client clientRequest = ClientBuilder.newClient();
        		try {
        			Response clientResponse = clientRequest.target(jwksUri).request().buildGet().invoke();

	                int status = clientResponse.getStatus();
	                log.debug(String.format("Status: %n%d", status));
	
	                if (status == 200) {
	                    jwks = clientResponse.readEntity(String.class);
	                    log.debug(String.format("JWK: %s", jwks));
	                }
        		} finally {
        			clientRequest.close();
        		}
            }
            if (StringHelper.isNotEmpty(jwks)) {
                JSONObject jsonObject = new JSONObject(jwks);
                JSONArray keys = jsonObject.getJSONArray(JSON_WEB_KEY_SET);
                if (keys.length() > 0) {
                    if (StringHelper.isEmpty(keyId)) {
                        jsonKey = keys.getJSONObject(0);
                    } else {
                        for (int i = 0; i < keys.length(); i++) {
                            JSONObject kv = keys.getJSONObject(i);
                            if (kv.getString(KEY_ID).equals(keyId)) {
                                jsonKey = kv;
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }

        return jsonKey;
    }

    public static JSONObject getJSONWebKeys(String jwksUri) {
        return getJSONWebKeys(jwksUri, null);
    }

    public static JSONObject getJSONWebKeys(String jwksUri, ClientHttpEngine engine) {
        log.debug("Retrieving jwks " + jwksUri + "...");

        JSONObject jwks = null;
        try {
            if (!StringHelper.isEmpty(jwksUri)) {
            	ClientBuilder clientBuilder = ResteasyClientBuilder.newBuilder();
            	if (engine != null) {
            		((ResteasyClientBuilder) clientBuilder).httpEngine(engine);
            	}

            	javax.ws.rs.client.Client clientRequest = clientBuilder.build();
        		try {
        			Response clientResponse = clientRequest.target(jwksUri).request().buildGet().invoke();

	                int status = clientResponse.getStatus();
	                log.debug(String.format("Status: %n%d", status));
	
	                if (status == 200) {
	                    jwks = fromJson(clientResponse.readEntity(String.class));
	                    log.debug(String.format("JWK: %s", jwks));
	                }
        		} finally {
        			clientRequest.close();
        		}
            }
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }

        return jwks;
    }

	public static JSONObject fromJson(String json) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JsonOrgModule());
		return mapper.readValue(json, JSONObject.class);
	}

	public static void transferIntoJwtClaims(JSONObject jsonObject, Jwt jwt) {
        if (jsonObject == null || jwt == null) {
            return;
        }

        for (String key : jsonObject.keySet()) {
            final Object value = jsonObject.opt(key);
            jwt.getClaims().setClaimObject(key, value, true);
        }
    }
}