/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.crypto.signature;

import org.apache.commons.lang.StringUtils;
import org.gluu.oxauth.model.crypto.Certificate;
import org.gluu.oxauth.model.crypto.KeyFactory;
import org.gluu.util.security.SecurityProviderUtility;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Factory to create asymmetric Public and Private Keys for the Elliptic Curve Digital Signature Algorithm (ECDSA)
 *
 * @author Javier Rojas Blum
 * @version June 15, 2016
 */
@SuppressWarnings("restriction")
public class ECDSAKeyFactory extends KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> {

    private SignatureAlgorithm signatureAlgorithm;
    private KeyPair keyPair;

    private ECDSAPrivateKey ecdsaPrivateKey;
    private ECDSAPublicKey ecdsaPublicKey;
    private Certificate certificate;

    public ECDSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, InvalidParameterSpecException, IOException, CertificateException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }

        this.signatureAlgorithm = signatureAlgorithm;

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", SecurityProviderUtility.getBCProvider());

        parameters.init(new ECGenParameterSpec(signatureAlgorithm.getCurve().getName()));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", SecurityProviderUtility.getBCProvider());
        keyGen.initialize(ecParameters, new SecureRandom());

        keyPair = keyGen.generateKeyPair();

        ECPrivateKey privateKeySpec = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKeySpec = (ECPublicKey) keyPair.getPublic();

        BigInteger x = publicKeySpec.getW().getAffineX();
        BigInteger y = publicKeySpec.getW().getAffineY();
        BigInteger s = privateKeySpec.getS();

        this.ecdsaPrivateKey = new ECDSAPrivateKey(s);
        this.ecdsaPublicKey = new ECDSAPublicKey(signatureAlgorithm, x, y);

        if (StringUtils.isNotBlank(dnName)) {
            final X509Certificate x509Certificate = genCertificate(dnName, CertificateVersion.V1);
            this.certificate = new Certificate(signatureAlgorithm, x509Certificate);
        }
    }

    public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName) throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, InvalidAlgorithmParameterException, IOException {
        final X509Certificate x509Certificate = genCertificate(dnName, CertificateVersion.V3);
        return new Certificate(signatureAlgorithm, x509Certificate);
    }

    @Override
    public ECDSAPrivateKey getPrivateKey() {
        return ecdsaPrivateKey;
    }

    @Override
    public ECDSAPublicKey getPublicKey() {
        return ecdsaPublicKey;
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
