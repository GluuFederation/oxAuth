/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.crypto.signature;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.gluu.oxauth.model.crypto.Certificate;
import org.gluu.oxauth.model.crypto.KeyFactory;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.oxauth.model.util.SecurityProviderUtility;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

/**
 * Factory to create asymmetric Public and Private Keys for the RSA algorithm
 *
 * @author Javier Rojas Blum
 * @version June 15, 2016
 */
@Deprecated
public class RSAKeyFactory extends KeyFactory<RSAPrivateKey, RSAPublicKey> {

    public static final int DEF_KEYLENGTH = 2048;

    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;
    private Certificate certificate;

    @Deprecated
    public RSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
            throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, CertificateEncodingException, CertificateException {
        if (signatureAlgorithm == null) {
            throw new InvalidParameterException("The signature algorithm cannot be null");
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", SecurityProviderUtility.getBCProvider(false).getName());
        keyGen.initialize(DEF_KEYLENGTH, new SecureRandom());

        KeyPair keyPair = keyGen.generateKeyPair();

    if (SecurityProviderUtility.hasFipsMode()) {
			AsymmetricRSAPrivateKey jcersaPrivateCrtKey = new AsymmetricRSAPrivateKey(FipsRSA.ALGORITHM,
					keyPair.getPrivate().getEncoded());
			AsymmetricRSAPublicKey jcersaPublicKey = new AsymmetricRSAPublicKey(FipsRSA.ALGORITHM,
					keyPair.getPublic().getEncoded());

			rsaPrivateKey = new RSAPrivateKey(jcersaPrivateCrtKey.getModulus(),
					jcersaPrivateCrtKey.getPrivateExponent());

			rsaPublicKey = new RSAPublicKey(jcersaPublicKey.getModulus(), jcersaPublicKey.getPublicExponent());

			if (StringUtils.isNotBlank(dnName)) {
				// Create certificate
				GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
				GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
				expiryDate.add(Calendar.YEAR, 1);
				BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate
				SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
				X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(new X500Name(dnName), serialNumber,
						startDate.getTime(), expiryDate.getTime(), new X500Name(dnName), subPubKeyInfo);

				JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(signatureAlgorithm.getAlgorithm());
				ContentSigner signer = csBuilder.build(keyPair.getPrivate());
				X509CertificateHolder certHolder = certGen.build(signer);
				X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BCFIPS")
						.getCertificate(certHolder);

				this.certificate = new Certificate(signatureAlgorithm, x509Certificate);

			}
		} else {
        BCRSAPrivateCrtKey jcersaPrivateCrtKey = (BCRSAPrivateCrtKey) keyPair.getPrivate();
        BCRSAPublicKey jcersaPublicKey = (BCRSAPublicKey) keyPair.getPublic();

        rsaPrivateKey = new RSAPrivateKey(jcersaPrivateCrtKey.getModulus(),
                jcersaPrivateCrtKey.getPrivateExponent());

        rsaPublicKey = new RSAPublicKey(jcersaPublicKey.getModulus(),
                jcersaPublicKey.getPublicExponent());

        if (StringUtils.isNotBlank(dnName)) {
            // Create certificate
            GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
            GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
            expiryDate.add(Calendar.YEAR, 1);
            BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate

            X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
            X500Principal principal = new X500Principal(dnName);

            certGen.setSerialNumber(serialNumber);
            certGen.setIssuerDN(principal);
            certGen.setNotBefore(startDate.getTime());
            certGen.setNotAfter(expiryDate.getTime());
            certGen.setSubjectDN(principal); // note: same as issuer
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm(signatureAlgorithm.getAlgorithm());

            X509Certificate x509Certificate = certGen.generate(jcersaPrivateCrtKey, SecurityProviderUtility.getBCProvider(false).getName());
            certificate = new Certificate(signatureAlgorithm, x509Certificate);
        }
    }
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

}