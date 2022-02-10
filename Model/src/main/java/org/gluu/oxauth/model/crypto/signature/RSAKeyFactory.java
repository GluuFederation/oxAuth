/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.crypto.signature;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.crypto.Certificate;
import org.gluu.oxauth.model.crypto.KeyFactory;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.util.security.SecurityProviderUtility;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Factory to create asymmetric Public and Private Keys for the RSA algorithm
 *
 * @author Javier Rojas Blum
 * @version June 15, 2016
 */
@SuppressWarnings("restriction")
@Deprecated
public class RSAKeyFactory extends KeyFactory<RSAPrivateKey, RSAPublicKey> {

    public static final int DEF_KEYLENGTH = 2048;

    private SignatureAlgorithm signatureAlgorithm;
    private KeyPair keyPair;

    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;
    private Certificate certificate;

    @Deprecated
    public RSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, CertificateException, InvalidAlgorithmParameterException, IOException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }

        this.signatureAlgorithm = signatureAlgorithm;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", SecurityProviderUtility.getBCProvider());
        keyGen.initialize(2048, new SecureRandom());

        keyPair = keyGen.generateKeyPair();

        java.security.interfaces.RSAPrivateKey jcersaPrivateCrtKey = (java.security.interfaces.RSAPrivateKey) keyPair.getPrivate();
        java.security.interfaces.RSAPublicKey jcersaPublicKey = (java.security.interfaces.RSAPublicKey) keyPair.getPublic();

        rsaPrivateKey = new RSAPrivateKey(jcersaPrivateCrtKey.getModulus(),
                jcersaPrivateCrtKey.getPrivateExponent());

        rsaPublicKey = new RSAPublicKey(jcersaPublicKey.getModulus(),
                jcersaPublicKey.getPublicExponent());

        if (StringUtils.isNotBlank(dnName)) {
            final X509Certificate x509Certificate = genCertificate(dnName, CertificateVersion.V1);
            this.certificate = new Certificate(signatureAlgorithm, x509Certificate);
        }
    }

    public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName) throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, InvalidAlgorithmParameterException, IOException {
        final X509Certificate x509Certificate = genCertificate(dnName, CertificateVersion.V3);
        return new Certificate(signatureAlgorithm, x509Certificate);
    }

    @Deprecated
    public RSAKeyFactory(JSONWebKey p_key) {
        if (p_key == null) {
            throw new IllegalArgumentException("Key value must not be null.");
        }

        rsaPrivateKey = new RSAPrivateKey(
                p_key.getN(),
                p_key.getE());
        rsaPublicKey = new RSAPublicKey(
                p_key.getN(),
                p_key.getE());
        certificate = null;
    }

    public static RSAKeyFactory valueOf(JSONWebKey p_key) {
        return new RSAKeyFactory(p_key);
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return rsaPrivateKey;
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return rsaPublicKey;
    }

    @Override
    public Certificate getCertificate() {
        return certificate;
    }

    private X509Certificate genCertificate(String dnName, int certVersion) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {

         X500Name x500Name = new X500Name(dnName);

         // Create certificate
         GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
         GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
         expiryDate.add(Calendar.YEAR, 1);

         PrivateKey privateKey = keyPair.getPrivate();
         PublicKey publicKey = keyPair.getPublic();

         CertificateValidity interval = new CertificateValidity(startDate.getTime(), expiryDate.getTime());

         X509CertInfo info = new X509CertInfo();

         AlgorithmParameterSpec params = AlgorithmId.getDefaultAlgorithmParameterSpec(signatureAlgorithm.getAlgorithm(), privateKey);

         // Add all mandatory attributes
         info.set(X509CertInfo.VERSION, new CertificateVersion(certVersion));
         info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
         AlgorithmId algID = AlgorithmId.getWithParameterSpec(signatureAlgorithm.getAlgorithm(), params);
         info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
         info.set(X509CertInfo.SUBJECT, x500Name);
         info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
         info.set(X509CertInfo.VALIDITY, interval);
         info.set(X509CertInfo.ISSUER, x500Name);

         X509CertImpl cert = new X509CertImpl(info);
         cert.sign(privateKey, params, signatureAlgorithm.getAlgorithm(), null);

         return (X509Certificate)cert;
     }
}