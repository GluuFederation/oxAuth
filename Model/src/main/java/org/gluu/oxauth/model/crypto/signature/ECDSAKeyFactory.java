/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.crypto.signature;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.gluu.oxauth.model.crypto.Certificate;
import org.gluu.oxauth.model.crypto.KeyFactory;
import org.gluu.oxauth.model.util.SecurityProviderUtility;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

/**
 * Factory to create asymmetric Public and Private Keys for the Elliptic Curve
 * Digital Signature Algorithm (ECDSA)
 *
 * @author Javier Rojas Blum
 * @version June 15, 2016
 */
public class ECDSAKeyFactory extends KeyFactory<ECDSAPrivateKey, ECDSAPublicKey> {

	private SignatureAlgorithm signatureAlgorithm;
	private KeyPair keyPair;

	private ECDSAPrivateKey ecdsaPrivateKey;
	private ECDSAPublicKey ecdsaPublicKey;
	private Certificate certificate;

	public ECDSAKeyFactory(SignatureAlgorithm signatureAlgorithm, String dnName)
			throws InvalidParameterException, NoSuchProviderException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, OperatorCreationException, CertificateException {
		if (signatureAlgorithm == null) {
			throw new InvalidParameterException("The signature algorithm cannot be null");
		}

		this.signatureAlgorithm = signatureAlgorithm;

		if(SecurityProviderUtility.hasFipsMode())
		{
			//X9ECParameters params = ECNamedCurveTable.getByName(signatureAlgorithm.getCurve().getName());
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", SecurityProviderUtility.getInstance(false).getName());
			keyGen.initialize(new ECGenParameterSpec(signatureAlgorithm.getCurve().getName()));
			this.keyPair = keyGen.generateKeyPair();
			
			AsymmetricECPrivateKey privateKeySpec = new AsymmetricECPrivateKey(FipsEC.ALGORITHM,
					keyPair.getPrivate().getEncoded());
			AsymmetricECPublicKey publicKeySpec = new AsymmetricECPublicKey(FipsEC.ALGORITHM,
					keyPair.getPublic().getEncoded());

			BigInteger x = publicKeySpec.getW().getXCoord().toBigInteger();
			BigInteger y = publicKeySpec.getW().getYCoord().toBigInteger();
			BigInteger d = privateKeySpec.getS();

			this.ecdsaPrivateKey = new ECDSAPrivateKey(d);
			this.ecdsaPublicKey = new ECDSAPublicKey(signatureAlgorithm, x, y);

			if (StringUtils.isNotBlank(dnName)) {
				// Create certificate
				GregorianCalendar startDate = new GregorianCalendar(); // time from which certificate is valid
				GregorianCalendar expiryDate = new GregorianCalendar(); // time after which certificate is not valid
				expiryDate.add(Calendar.YEAR, 1);
				BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate
				X500Name principal = new X500Name(dnName);
				SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
				X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(principal, serialNumber,
						startDate.getTime(), expiryDate.getTime(), principal, subPubKeyInfo);

				JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256WITHECDSA");
				ContentSigner signer = csBuilder.build(keyPair.getPrivate());
				X509CertificateHolder certHolder = certGen.build(signer);
				X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(SecurityProviderUtility.getInstance(false).getName())
						.getCertificate(certHolder);

				this.certificate = new Certificate(signatureAlgorithm, x509Certificate);
			}
		}
		else
		{
				ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(signatureAlgorithm.getCurve().getName());

		        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", SecurityProviderUtility.getInstance(false).getName());
		        keyGen.initialize(ecSpec, new SecureRandom());

		        this.keyPair = keyGen.generateKeyPair();
		        BCECPrivateKey privateKeySpec = (BCECPrivateKey) keyPair.getPrivate();
		        BCECPublicKey publicKeySpec = (BCECPublicKey) keyPair.getPublic();

		        BigInteger x = publicKeySpec.getQ().getXCoord().toBigInteger();
		        BigInteger y = publicKeySpec.getQ().getYCoord().toBigInteger();
		        BigInteger d = privateKeySpec.getD();

		        this.ecdsaPrivateKey = new ECDSAPrivateKey(d);
		        this.ecdsaPublicKey = new ECDSAPublicKey(signatureAlgorithm, x, y);

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
		            certGen.setSignatureAlgorithm("SHA256WITHECDSA");

		            X509Certificate x509Certificate = certGen.generate(privateKeySpec, SecurityProviderUtility.getInstance(false).getName());
		            this.certificate = new Certificate(signatureAlgorithm, x509Certificate);
		        }
		}
		
	}

	public Certificate generateV3Certificate(Date startDate, Date expirationDate, String dnName)
			throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, OperatorCreationException, CertificateException {

		if (SecurityProviderUtility.hasFipsMode()) {
			// Create certificate
			BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate

			// X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
			X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(new X500Name(dnName), serialNumber,
					startDate, expirationDate, new X500Name(dnName), subPubKeyInfo);
			X500Principal principal = new X500Principal(dnName);

			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(signatureAlgorithm.getAlgorithm());
			ContentSigner signer = csBuilder.build(keyPair.getPrivate());
			X509CertificateHolder certHolder = certGen.build(signer);
			X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(SecurityProviderUtility.getInstance(false).getName())
					.getCertificate(certHolder);

			return new Certificate(signatureAlgorithm, x509Certificate);
		} else {
			BigInteger serialNumber = new BigInteger(1024, new Random()); // serial number for certificate

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal principal = new X500Principal(dnName);

			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(principal);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expirationDate);
			certGen.setSubjectDN(principal); // note: same as issuer
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm(signatureAlgorithm.getAlgorithm());

			X509Certificate x509Certificate = certGen.generate(keyPair.getPrivate(), SecurityProviderUtility.getInstance(false).getName());
			return new Certificate(signatureAlgorithm, x509Certificate);
		}
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
}