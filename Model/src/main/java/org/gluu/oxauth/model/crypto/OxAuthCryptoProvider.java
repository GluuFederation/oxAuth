/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.crypto;

import com.google.common.collect.Lists;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.gluu.oxauth.model.configuration.AppConfiguration;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.jwk.KeySelectionStrategy;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.oxauth.model.util.CertUtils;
import org.gluu.oxauth.model.util.Util;
import org.gluu.util.security.SecurityProviderUtility;
import org.gluu.util.security.SecurityProviderUtility.SecurityModeType;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

import static org.gluu.oxauth.model.jwk.JWKParameter.*;

/**
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @author Sergey Manoylo
 * @version April 25, 2022
 */
public class OxAuthCryptoProvider extends AbstractCryptoProvider {

    protected static final Logger LOG = Logger.getLogger(OxAuthCryptoProvider.class);

    private KeyStore keyStore;
    private String keyStoreFile;
    private String keyStoreSecret;
    private String dnName;
    private final boolean rejectNoneAlg;
    private final KeySelectionStrategy keySelectionStrategy;

    public OxAuthCryptoProvider() throws Exception {
        this(null, null, null);
    }

    public OxAuthCryptoProvider(String keyStoreFile, String keyStoreSecret, String dnName) throws Exception {
        this(keyStoreFile, keyStoreSecret, dnName, false);
    }

    public OxAuthCryptoProvider(String keyStoreFile, String keyStoreSecret, String dnName, boolean rejectNoneAlg) throws Exception {
        this(keyStoreFile, keyStoreSecret, dnName, rejectNoneAlg, AppConfiguration.DEFAULT_KEY_SELECTION_STRATEGY);
    }

    public OxAuthCryptoProvider(String keyStoreFile, String keyStoreSecret, String dnName, boolean rejectNoneAlg, KeySelectionStrategy keySelectionStrategy) throws Exception {
        this.rejectNoneAlg = rejectNoneAlg;
        this.keySelectionStrategy = keySelectionStrategy != null ? keySelectionStrategy : AppConfiguration.DEFAULT_KEY_SELECTION_STRATEGY;
        if (!Util.isNullOrEmpty(keyStoreFile) && !Util.isNullOrEmpty(keyStoreSecret) /* && !Util.isNullOrEmpty(dnName) */) {
            this.keyStoreFile = keyStoreFile;
            this.keyStoreSecret = keyStoreSecret;
            this.dnName = dnName;
            SecurityProviderUtility.KeyStorageType keyStorageType = solveKeyStorageType();
            switch (keyStorageType) {
            case JKS_KS: {
                keyStore = KeyStore.getInstance("JKS");
                break;
            }
            case PKCS12_KS: {
                keyStore = KeyStore.getInstance("PKCS12", SecurityProviderUtility.getBCProvider());
                break;
            }
            case BCFKS_KS: {
                keyStore = KeyStore.getInstance("BCFKS", SecurityProviderUtility.getBCProvider());
                break;
            }
            }
            try {
                File f = new File(keyStoreFile);
                if (!f.exists()) {
                    keyStore.load(null, keyStoreSecret.toCharArray());
                    FileOutputStream fos = new FileOutputStream(keyStoreFile);
                    keyStore.store(fos, keyStoreSecret.toCharArray());
                    fos.close();
                }
                final InputStream is = new FileInputStream(keyStoreFile);
                keyStore.load(is, keyStoreSecret.toCharArray());
                LOG.debug("Loaded keys from keystore.");
                LOG.debug("Security Mode: " + SecurityProviderUtility.getSecurityMode().toString());
                LOG.debug("Keystore Type: " + keyStorageType.toString());
                LOG.trace("Loaded keys:"+ getKeys());
            } catch (Exception e) {
                LOG.error(e.getMessage(), e);
                LOG.error("Check type of keystorage. Expected keystorage type: '" + keyStorageType.toString() + "'");
            }
        }
    }

    public void load(String keyStoreSecret) {
        this.keyStoreSecret = keyStoreSecret;
        SecurityProviderUtility.KeyStorageType keyStorageType = solveKeyStorageType();
        try(InputStream is = new FileInputStream(keyStoreFile)) {
            switch (keyStorageType) {
            case JKS_KS: {
                keyStore = KeyStore.getInstance("JKS");
                break;
            }
            case PKCS12_KS: {
                keyStore = KeyStore.getInstance("PKCS12", SecurityProviderUtility.getBCProvider());
                break;
            }
            case BCFKS_KS: {
                keyStore = KeyStore.getInstance("BCFKS", SecurityProviderUtility.getBCProvider());
                break;
            }
            }
            keyStore.load(is, keyStoreSecret.toCharArray());
            LOG.debug("Loaded keys from keystore.");
            LOG.debug("Security Mode: " + SecurityProviderUtility.getSecurityMode().toString());
            LOG.debug("Keystore Type: " + keyStorageType.toString());
            LOG.trace("Loaded keys:"+ getKeys());
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            LOG.error("Check type of keystorage. Expected keystorage type: '" + keyStorageType.toString() + "'");
        }
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public String getKeyStoreSecret() {
        return keyStoreSecret;
    }

    public String getDnName() {
        return dnName;
    }

    @Override
    public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception {
        return generateKey(algorithm, expirationTime, use, 2048);
    }

    @Override
    public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use, int keyLength) throws Exception {

        KeyPairGenerator keyGen = null;

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());
        if (signatureAlgorithm == null) {
            signatureAlgorithm = SignatureAlgorithm.RS256;
        }

        if (algorithm == null) {
            throw new RuntimeException("The signature algorithm parameter cannot be null");
        } else if (AlgorithmFamily.RSA.equals(algorithm.getFamily())) {
            keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(), SecurityProviderUtility.getBCProvider());
            keyGen.initialize(keyLength, new SecureRandom());

        } else if (AlgorithmFamily.EC.equals(algorithm.getFamily())) {
            ECGenParameterSpec eccgen = new ECGenParameterSpec(signatureAlgorithm.getCurve().getAlias());
            keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(), SecurityProviderUtility.getBCProvider());
            keyGen.initialize(eccgen, new SecureRandom());
        } else {
            throw new RuntimeException("The provided signature algorithm parameter is not supported");
        }

        // Generate the key
        KeyPair keyPair = keyGen.generateKeyPair();
        java.security.PrivateKey pk = keyPair.getPrivate();

        // Java API requires a certificate chain
        X509Certificate cert = generateV3Certificate(keyPair, dnName, signatureAlgorithm.getAlgorithm(), expirationTime);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        String alias = UUID.randomUUID().toString() + getKidSuffix(use, algorithm);
        keyStore.setKeyEntry(alias, pk, keyStoreSecret.toCharArray(), chain);

        final String oldAliasByAlgorithm = getAliasByAlgorithmForDeletion(algorithm, alias, use);
        if (StringUtils.isNotBlank(oldAliasByAlgorithm)) {
            keyStore.deleteEntry(oldAliasByAlgorithm);
            LOG.trace("New key: " + alias + ", deleted key: " + oldAliasByAlgorithm);
        }

        FileOutputStream stream = new FileOutputStream(keyStoreFile);
        keyStore.store(stream, keyStoreSecret.toCharArray());
        stream.close();

        PublicKey publicKey = keyPair.getPublic();

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(KEY_TYPE, algorithm.getFamily());
        jsonObject.put(KEY_ID, alias);
        jsonObject.put(KEY_USE, use.getParamName());
        jsonObject.put(ALGORITHM, algorithm.getParamName());
        jsonObject.put(EXPIRATION_TIME, expirationTime);
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            jsonObject.put(MODULUS, Base64Util.base64urlencodeUnsignedBigInt(rsaPublicKey.getModulus()));
            jsonObject.put(EXPONENT, Base64Util.base64urlencodeUnsignedBigInt(rsaPublicKey.getPublicExponent()));
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            jsonObject.put(CURVE, signatureAlgorithm.getCurve().getName());
            jsonObject.put(X, Base64Util.base64urlencodeUnsignedBigInt(ecPublicKey.getW().getAffineX()));
            jsonObject.put(Y, Base64Util.base64urlencodeUnsignedBigInt(ecPublicKey.getW().getAffineY()));
        }
        JSONArray x5c = new JSONArray();
        x5c.put(Base64.encodeBase64String(cert.getEncoded()));
        jsonObject.put(CERTIFICATE_CHAIN, x5c);

        return jsonObject;
    }

    private static String getKidSuffix(Use use, Algorithm algorithm) {
        return "_" + use.getParamName().toLowerCase() + "_" + algorithm.getParamName().toLowerCase();
    }

    public String getAliasByAlgorithmForDeletion(Algorithm algorithm, String newAlias, Use use) throws KeyStoreException {
        for (String alias : Collections.list(keyStore.aliases())) {

            if (newAlias.equals(alias)) { // skip newly created alias
                continue;
            }

            if (alias.endsWith(getKidSuffix(use, algorithm))) {
                return alias;
            }
        }
        return null;
    }

    @Override
    public boolean containsKey(String keyId) {
        try {
            if (StringUtils.isBlank(keyId)){
                return false;
            }
            return keyStore.getKey(keyId, keyStoreSecret.toCharArray()) != null;
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            return false;
        }
    }

    @Override
    public String sign(String signingInput, String alias, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        if (signatureAlgorithm == SignatureAlgorithm.NONE) {
            return "";
        } else if (AlgorithmFamily.HMAC.equals(signatureAlgorithm.getFamily())) {
            SecretKey secretKey = new SecretKeySpec(sharedSecret.getBytes(Util.UTF8_STRING_ENCODING), signatureAlgorithm.getAlgorithm());
            Mac mac = Mac.getInstance(signatureAlgorithm.getAlgorithm());
            mac.init(secretKey);
            byte[] sig = mac.doFinal(signingInput.getBytes());
            return Base64Util.base64urlencode(sig);
        } else { // EC or RSA
            PrivateKey privateKey = getPrivateKey(alias);
            if (privateKey == null) {
                final String error = "Failed to find private key by kid: " + alias +
                        ", signatureAlgorithm: " + signatureAlgorithm +
                        "(check whether web keys JSON in persistence corresponds to keystore file), keySelectionStrategy: " + keySelectionStrategy;
                LOG.error(error);
                throw new RuntimeException(error);
            }

            Signature signer = Signature.getInstance(signatureAlgorithm.getAlgorithm(), SecurityProviderUtility.getBCProvider());
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes());

            byte[] signature = signer.sign();
            if (AlgorithmFamily.EC.equals(signatureAlgorithm.getFamily())) {
            	int signatureLenght = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.parse(signatureAlgorithm.getName()));
                signature = ECDSA.transcodeSignatureToConcat(signature, signatureLenght);
            }

            return Base64Util.base64urlencode(signature);
        }
    }

    @Override
    public boolean verifySignature(String signingInput, String encodedSignature, String alias, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        if (rejectNoneAlg && signatureAlgorithm == SignatureAlgorithm.NONE) {
            LOG.trace("None algorithm is forbidden by `rejectJwtWithNoneAlg` property.");
            return false;
        }

        if (signatureAlgorithm == SignatureAlgorithm.NONE) {
            return Util.isNullOrEmpty(encodedSignature);
        } else if (AlgorithmFamily.HMAC.equals(signatureAlgorithm.getFamily())) {
            String expectedSignature = sign(signingInput, null, sharedSecret, signatureAlgorithm);
            return expectedSignature.equals(encodedSignature);
        } else { // EC or RSA
            PublicKey publicKey = null;

            try {
                if (jwks == null) {
                    publicKey = getPublicKey(alias);
                } else {
                    publicKey = getPublicKey(alias, jwks, signatureAlgorithm.getAlg());
                }
                if (publicKey == null) {
                    return false;
                }

                byte[] signature = Base64Util.base64urldecode(encodedSignature);
                byte[] signatureDer = signature;
                if (AlgorithmFamily.EC.equals(signatureAlgorithm.getFamily())) {
                	signatureDer = ECDSA.transcodeSignatureToDER(signatureDer);
                }

                Signature verifier = Signature.getInstance(signatureAlgorithm.getAlgorithm(), SecurityProviderUtility.getBCProvider());
                verifier.initVerify(publicKey);
                verifier.update(signingInput.getBytes());
                try {
                	return verifier.verify(signatureDer);
                } catch (SignatureException e) {
                	// Fall back to old format
                	// TODO: remove in Gluu 5.0
                	return verifier.verify(signature);
                }
            } catch (Exception e) {
                LOG.error(e.getMessage(), e);
                return false;
            }
        }
    }

    private String getJWKSValue(JSONObject jwks, String node) throws JSONException {
        try {
            return jwks.getString(node);
        } catch (Exception ex) {
            JSONObject publicKey = jwks.getJSONObject(PUBLIC_KEY);
            return publicKey.getString(node);
        }
    }

    @Override
    public boolean deleteKey(String alias) throws Exception {
        keyStore.deleteEntry(alias);
        FileOutputStream stream = new FileOutputStream(keyStoreFile);
        keyStore.store(stream, keyStoreSecret.toCharArray());
        stream.close();
        return true;
    }

    public PublicKey getPublicKey(String alias) {
        PublicKey publicKey = null;

        try {
            if (Util.isNullOrEmpty(alias)) {
                return null;
            }

            java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
            if (certificate == null) {
                return null;
            }
            publicKey = certificate.getPublicKey();

            checkKeyExpiration(alias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public String getKeyId(JSONWebKeySet jsonWebKeySet, Algorithm algorithm, Use use) throws Exception {
        if (algorithm == null || AlgorithmFamily.HMAC.equals(algorithm.getFamily())) {
            return null;
        }

        String kid = null;
        final List<JSONWebKey> keys = jsonWebKeySet.getKeys();
        LOG.trace("WebKeys:" + keys.stream().map(JSONWebKey::getKid).collect(Collectors.toList()));
        LOG.trace("KeyStoreKeys:" + getKeys());

        List<JSONWebKey> keysByAlgAndUse = new ArrayList<>();

        for (JSONWebKey key : keys) {
            if (algorithm == key.getAlg() && (use == null || use == key.getUse())) {
                kid = key.getKid();
                Key keyFromStore = keyStore.getKey(kid, keyStoreSecret.toCharArray());
                if (keyFromStore != null) {
                    keysByAlgAndUse.add(key);
                }
            }
        }

        if (keysByAlgAndUse.isEmpty()) {
            LOG.trace("kid is not in keystore, algorithm: " + algorithm + ", kid: " + kid + ", keyStorePath:" + keyStoreFile);
            return kid;
        }

        if (LOG.isTraceEnabled())
            LOG.trace("Select among keys (älg: "+ algorithm+", use: " + use + "): " + traceWithExp(keysByAlgAndUse));
        final JSONWebKey selectedKey = keySelectionStrategy.select(keysByAlgAndUse);
        final String selectedKid = selectedKey != null ? selectedKey.getKid() : null;
        LOG.trace("Selected kid: " + selectedKid + ", keySelectionStrategy: " + keySelectionStrategy);
        return selectedKid;
    }

    private String traceWithExp(List<JSONWebKey> list) {
        StringBuilder sb = new StringBuilder("[");
        for (JSONWebKey key : list)
            sb.append("{\"kid\":").append(key.getKid()).append(",\"exp\":").append(key.getExp()).append("},");
        sb.append("]");
        return sb.toString();
    }

    public PrivateKey getPrivateKey(String alias)
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        if (Util.isNullOrEmpty(alias)) {
            return null;
        }

        Key key = keyStore.getKey(alias, keyStoreSecret.toCharArray());
        if (key == null) {
            return null;
        }
        PrivateKey privateKey = (PrivateKey) key;

        checkKeyExpiration(alias);

        return privateKey;
    }

    public X509Certificate generateV3Certificate(KeyPair keyPair, String issuer, String signatureAlgorithm, Long expirationTime) throws CertIOException, OperatorCreationException, CertificateException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Signers name
        X500Name issuerName = new X500Name(issuer);

        // Subjects name - the same as we are self signed.
        X500Name subjectName = new X500Name(issuer);

        // Serial
        BigInteger serial = new BigInteger(256, new SecureRandom());

        // Not before
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(expirationTime);

        // Create the certificate - version 3
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, publicKey);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);

        ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37").intern();
        builder.addExtension(extendedKeyUsage, false, new DERSequence(purposes));

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(SecurityProviderUtility.getBCProvider()).build(privateKey);
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(SecurityProviderUtility.getBCProvider()).getCertificate(holder);

        return cert;
    }

    public List<String> getKeys() {
        try {
            return Collections.list(this.keyStore.aliases());
        } catch (KeyStoreException e) {
            LOG.error(e.getMessage(), e);
            return Lists.newArrayList();
        }
    }

    public SignatureAlgorithm getSignatureAlgorithm(String alias) throws KeyStoreException {
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if ((chain == null) || chain.length == 0) {
            return null;
        }

        X509Certificate cert = (X509Certificate) chain[0];
        return CertUtils.getSignatureAlgorithm(cert);
    }


    private void checkKeyExpiration(String alias) {
        try {
            Date expirationDate = ((X509Certificate) keyStore.getCertificate(alias)).getNotAfter();
            checkKeyExpiration(alias, expirationDate.getTime());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Checks, if SecurityModeType value correspondent to the keystorage extension value
     *
     * @param extension extension value
     * @param securityMode SecurityModeType value
     * @return boolean result
     */
    public static boolean checkExtension(final String extension, final SecurityModeType securityMode) {
        boolean res = false;
        if (securityMode != null) {
            res = securityMode.toString().equals(extension);
        }
        return res;
    }

    /**
     * 
     * @return
     */
    private SecurityProviderUtility.KeyStorageType solveKeyStorageType() {
        SecurityProviderUtility.SecurityModeType securityMode = SecurityProviderUtility.getSecurityMode();
        if (securityMode == null) {
            throw new InvalidParameterException("Security Mode wasn't initialized. Call installBCProvider() before");
        }
        String keyStoreExt = FilenameUtils.getExtension(keyStoreFile);
        SecurityProviderUtility.KeyStorageType keyStorageType = SecurityProviderUtility.KeyStorageType.fromExtension(keyStoreExt);
        boolean ksTypeFound = false;
        for (SecurityProviderUtility.KeyStorageType ksType : securityMode.getKeystorageTypes()) {
            if (keyStorageType == ksType) {
                ksTypeFound = true;
                break;
            }
        }
        if (!ksTypeFound) {
            switch (securityMode) {
            case BCFIPS_SECURITY_MODE: {
                keyStorageType =  SecurityProviderUtility.KeyStorageType.BCFKS_KS;
                break;
            }
            case BCPROV_SECURITY_MODE: {
                keyStorageType = SecurityProviderUtility.KeyStorageType.PKCS12_KS;
                break;
            }
            }
        }
        return keyStorageType;
    }
}