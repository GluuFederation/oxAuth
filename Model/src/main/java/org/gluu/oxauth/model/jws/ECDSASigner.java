/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.jws;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import org.gluu.oxauth.model.crypto.Certificate;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.crypto.signature.ECDSAPrivateKey;
import org.gluu.oxauth.model.crypto.signature.ECDSAPublicKey;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.oxauth.model.util.Util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;

/**
 * @author Javier Rojas Blum
 * @version July 31, 2016
 */
public class ECDSASigner extends AbstractJwsSigner {

    private ECDSAPrivateKey ecdsaPrivateKey;
    private ECDSAPublicKey ecdsaPublicKey;

    public ECDSASigner(SignatureAlgorithm signatureAlgorithm, ECDSAPrivateKey ecdsaPrivateKey) {
        super(signatureAlgorithm);
        this.ecdsaPrivateKey = ecdsaPrivateKey;
    }

    public ECDSASigner(SignatureAlgorithm signatureAlgorithm, ECDSAPublicKey ecdsaPublicKey) {
        super(signatureAlgorithm);
        this.ecdsaPublicKey = ecdsaPublicKey;
    }

    public ECDSASigner(SignatureAlgorithm signatureAlgorithm, Certificate certificate) {
        super(signatureAlgorithm);
        this.ecdsaPublicKey = certificate.getEcdsaPublicKey();
    }

    @Override
    public String generateSignature(String signingInput) throws SignatureException {
        if (getSignatureAlgorithm() == null) {
            throw new SignatureException("The signature algorithm is null");
        }
        if (ecdsaPrivateKey == null) {
            throw new SignatureException("The ECDSA private key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }

        try {
        	// TODO: check this part
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(getSignatureAlgorithm().getCurve().getName());
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
            g.initialize(ecSpec, new SecureRandom());
            KeyPair keypair = g.generateKeyPair();
            //PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();
            
           // ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(ecdsaPrivateKey.getD(), ecSpec);

            //KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BCFIPS");
            //PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            Signature signer = Signature.getInstance(getSignatureAlgorithm().getAlgorithm(), "BCFIPS");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(Util.UTF8_STRING_ENCODING));

            byte[] signature = signer.sign();
            if (AlgorithmFamily.EC.equals(getSignatureAlgorithm().getFamily())) {
            	int signatureLenght = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.parse(getSignatureAlgorithm().getName()));
                signature = ECDSA.transcodeSignatureToConcat(signature, signatureLenght);
            }

            return Base64Util.base64urlencode(signature);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
    }

    @Override
    public boolean validateSignature(String signingInput, String signature) throws SignatureException {
        if (getSignatureAlgorithm() == null) {
            throw new SignatureException("The signature algorithm is null");
        }
        if (ecdsaPublicKey == null) {
            throw new SignatureException("The ECDSA public key is null");
        }
        if (signingInput == null) {
            throw new SignatureException("The signing input is null");
        }

        String algorithm;
        String curve;
        switch (getSignatureAlgorithm()) {
            case ES256:
                algorithm = "SHA256WITHECDSA";
                curve = "P-256";
                break;
            case ES384:
                algorithm = "SHA384WITHECDSA";
                curve = "P-384";
                break;
            case ES512:
                algorithm = "SHA512WITHECDSA";
                curve = "P-521";
                break;
            default:
                throw new SignatureException("Unsupported signature algorithm");
        }

        try {
            byte[] sigBytes = Base64Util.base64urldecode(signature);
            if (AlgorithmFamily.EC.equals(getSignatureAlgorithm().getFamily())) {
                sigBytes = ECDSA.transcodeSignatureToDER(sigBytes);
            }
            byte[] sigInBytes = signingInput.getBytes(Util.UTF8_STRING_ENCODING);

            //TODO: how is this done?
            
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(getSignatureAlgorithm().getCurve().getName());
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
            g.initialize(ecSpec, new SecureRandom());
            KeyPair keypair = g.generateKeyPair();
            PublicKey publicKey = keypair.getPublic();
            Signature sig = Signature.getInstance(algorithm, "BCFIPS");
            sig.initVerify(publicKey);
            sig.update(sigInBytes);
            return sig.verify(sigBytes);
        } catch (InvalidKeyException e) {
            throw new SignatureException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        } catch (NoSuchProviderException e) {
            throw new SignatureException(e);
        } catch (UnsupportedEncodingException e) {
            throw new SignatureException(e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
    }
}