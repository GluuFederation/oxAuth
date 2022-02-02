/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.fido.u2f;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.gluu.oxauth.crypto.signature.SHA256withECDSASignatureVerification;
import org.gluu.oxauth.model.exception.SignatureException;
import org.gluu.oxauth.model.fido.u2f.exception.BadInputException;
import org.gluu.oxauth.model.fido.u2f.message.RawAuthenticateResponse;
import org.gluu.oxauth.model.fido.u2f.protocol.ClientData;
import org.gluu.oxauth.model.util.Base64Util;
import org.gluu.util.io.ByteDataInputStream;
import org.slf4j.Logger;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;

/**
 * Provides operations with U2F RAW authentication response
 *
 * @author Yuriy Movchan Date: 05/20/2015
 */
@ApplicationScoped
public class RawAuthenticationService {

	public static final String AUTHENTICATE_GET_TYPE = "navigator.id.getAssertion";
	public static final String AUTHENTICATE_CANCEL_TYPE = "navigator.id.cancelAssertion";
	public static final String[] SUPPORTED_AUTHENTICATE_TYPES = new String[] { AUTHENTICATE_GET_TYPE, AUTHENTICATE_CANCEL_TYPE };

	@Inject
	private Logger log;

	@Inject @Named(value = "sha256withECDSASignatureVerification")
	private SHA256withECDSASignatureVerification signatureVerification;

	public RawAuthenticateResponse parseRawAuthenticateResponse(String rawDataBase64) {
		ByteDataInputStream bis = new ByteDataInputStream(Base64Util.base64urldecode(rawDataBase64));
		try {
			return new RawAuthenticateResponse(bis.readSigned(), bis.readInt(), bis.readAll());
		} catch (IOException ex) {
			throw new BadInputException("Failed to parse RAW authenticate response", ex);
		} finally {
			IOUtils.closeQuietly(bis);
		}
	}

	public void checkSignature(String appId, ClientData clientData, RawAuthenticateResponse rawAuthenticateResponse, byte[] publicKey) throws BadInputException {
		String rawClientData = clientData.getRawClientData();

		byte[] signedBytes = packBytesToSign(signatureVerification.hash(appId), rawAuthenticateResponse.getUserPresence(),
				rawAuthenticateResponse.getCounter(), signatureVerification.hash(rawClientData));

		log.debug("Packed bytes to sign in HEX '{}'", Hex.encodeHexString(signedBytes));
		log.debug("Signature from authentication response in HEX '{}'", Hex.encodeHexString(rawAuthenticateResponse.getSignature()));
		try {
			boolean isValid = signatureVerification.checkSignature(signatureVerification.decodePublicKey(publicKey), signedBytes, rawAuthenticateResponse.getSignature());
			if (!isValid) {
				throw new BadInputException("Signature is not valid");
			}
		} catch (SignatureException ex) {
			throw new BadInputException("Failed to checkSignature", ex);
		}
	}

	private byte[] packBytesToSign(byte[] appIdHash, byte userPresence, long counter, byte[] challengeHash) {
		ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
		encoded.write(appIdHash);
		encoded.write(userPresence);
		encoded.writeInt((int) counter);
		encoded.write(challengeHash);

		return encoded.toByteArray();
	}

}
