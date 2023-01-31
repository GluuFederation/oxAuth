package org.gluu.oxauth.service.fido.u2f;

import static org.testng.Assert.assertTrue;

import java.math.BigInteger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.gluu.oxauth.crypto.signature.SHA256withECDSASignatureVerification;
import org.gluu.oxauth.crypto.signature.SignatureVerification;
import org.gluu.oxauth.model.exception.SignatureException;
import org.gluu.oxauth.model.fido.u2f.exception.BadInputException;
import org.gluu.oxauth.model.fido.u2f.message.RawAuthenticateResponse;
import org.gluu.oxauth.model.fido.u2f.message.RawRegisterResponse;
import org.gluu.oxauth.model.fido.u2f.protocol.AuthenticateResponse;
import org.gluu.oxauth.model.fido.u2f.protocol.ClientData;
import org.gluu.oxauth.model.fido.u2f.protocol.RegisterResponse;
import org.gluu.oxauth.util.ServerUtil;
import org.gluu.util.security.SecurityProviderUtility;
import org.testng.annotations.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;

public class RawAuthenticationServiceUnitTest {

	@Test
	public void checkSignatureVerification() throws DecoderException, SignatureException {
		SecurityProviderUtility.installBCProvider();

		String signedDataHex = "415141414141677752674968414c4f4f62544e55506677772d643669776c6a6132636f714134473561374f4156534e744b4462513034717341694541684a734542745072494a49766436636e595351454842415549723644395839794e70636c6166544c797749";
		byte[] signedData = Hex.decodeHex(signedDataHex);

		String signatureDataHex = "3046022100b38e6d33543dfc30f9dea2c258dad9ca2a0381b96bb38055236d2836d0d38aac022100849b0406d3eb20922f77a7276124041c101422be83f57f7236972569f4cbcb02";
		byte[] signatureData = Hex.decodeHex(signatureDataHex);

		String publicKeyHex = "04e9a52ef1136d1eee973c700bd86e1dd314dc04373d47f1219d1f8c286c9f30311fdbb158eaceac60e3a7a0298c94269878c5ec6853004182e126cdb72254edc2";
		byte[] publicKey = Hex.decodeHex(publicKeyHex);

		SignatureVerification signatureVerification = new SHA256withECDSASignatureVerification();

		boolean isValid = signatureVerification.checkSignature(signatureVerification.decodePublicKey(publicKey),
				signedData, signatureData);
		assertTrue(isValid);
	}

	@Test
	public void checkAttestationSignature() throws DecoderException, SignatureException, JsonMappingException, JsonProcessingException {
		SecurityProviderUtility.installBCProvider();

		String registerResponseString = "{\"registrationData\":\"BQTE0bf7K1WtbQ3yVhwK3IF9yRysjpY8vvf_nmYjGfOGHE648BDGJf6QPcZpz5n9FAT0P_Jb2KpnQ6kkOpFTbXXpQEvRYV5pcRtZWCjnGjzMLzK9dfyzAxjKB6-3YZxxSLKwpJ0Ye6ryx72TqWZmfdz30UiYsXhd_JKyMONw05BL70QwggImMIIBzKADAgECAoGBAPMsD5b5G58AphKuKWl4Yz27sbE_rXFy7nPRqtJ_r4E5DSZbFvfyuos-Db0095ubB0JoyM8ccmSO_eZQ6IekOLPKCR7yC5kes-f7MaxyaphmmD4dEvmuKjF-fRsQP5tQG7zerToto8eIz0XjPaupiZxQXtSHGHHTuPhri2nfoZlrMAoGCCqGSM49BAMCMFwxIDAeBgNVBAMTF0dsdXUgb3hQdXNoMiBVMkYgdjEuMC4wMQ0wCwYDVQQKEwRHbHV1MQ8wDQYDVQQHEwZBdXN0aW4xCzAJBgNVBAgTAlRYMQswCQYDVQQGEwJVUzAeFw0xNjAzMDExODU5NDZaFw0xOTAzMDExODU5NDZaMFwxIDAeBgNVBAMTF0dsdXUgb3hQdXNoMiBVMkYgdjEuMC4wMQ0wCwYDVQQKEwRHbHV1MQ8wDQYDVQQHEwZBdXN0aW4xCzAJBgNVBAgTAlRYMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABICUKnzCE5PJ7tihiKkYu6E5Uy_sZ-RSqs_MnUJt0tB8G8GSg9nKo6P2424iV9lXX9Pil8qw4ofZ-fAXXepbp4MwCgYIKoZIzj0EAwIDSAAwRQIgUWwawAB2udURWQziDXVjSOi_QcuXiRxylqj5thFwFhYCIQCGY-CTZFi7JdkhZ05nDpbSYJBTOo1Etckh7k0qcvnO0TBGAiEArL4uk9i4_r1XJOHx5sf0RsGWfqYz-r0k-i8oDX7NSqcCIQCZt_yIraDAN3exvYofvAHoPi_QAYcVOuXv9TXbfLToiQ\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IlhCSWZ4THY0U054Wk9MR3FwbUFHVFlHTHkwLTBKR3BDYmJJY3lnMVppQUEiLCJvcmlnaW4iOiJodHRwczpcL1wvdTIwNC5qYW5zLmluZm8ifQ\",\"deviceData\":\"eyJuYW1lIjoiU00tRzk5MUIiLCJvc19uYW1lIjoidGlyYW1pc3UiLCJvc192ZXJzaW9uIjoiMTMiLCJwbGF0Zm9ybSI6ImFuZHJvaWQiLCJwdXNoX3Rva2VuIjoiYzh2am5lallEdXc6QVBBOTFiR0J3VkNnaURFQXE2R3MzRXhBZ2JzNG1qV0NXa0lJSEE4MVZDNGd3MFFBR1gzR0ZyQUZEbE9NQ3hYWkh0dGhZeS1vd1dEVlRzV3p2QTJXdXJEd1BfOFVNbHZZWUlmYzhjc0FidV9ZN1gtQXVsaG5NNnlxMzJMeTl4QmlvZmI2N0h1VVZRVnIiLCJ0eXBlIjoibm9ybWFsIiwidXVpZCI6IjNmZTYwNjljLTAxMTItMzJkMC1hZDYwLTU3NjI0ZmZhNTg0NCJ9\"}";

		RegisterResponse registerResponse = ServerUtil.jsonMapperWithWrapRoot().readValue(registerResponseString, RegisterResponse.class);
        RawRegisterResponse rawRegisterResponse = (new RawRegistrationService()).parseRawRegisterResponse(registerResponse.getRegistrationData());

		SignatureVerification signatureVerification = new SHA256withECDSASignatureVerification();

		byte[] signedBytes = packBytesToAttestationSign(signatureVerification.hash(registerResponse.getClientData().getOrigin()),
				signatureVerification.hash(registerResponse.getClientData().getChallenge()), rawRegisterResponse.getKeyHandle(),
				rawRegisterResponse.getUserPublicKey());

		boolean isValid = signatureVerification.checkSignature(rawRegisterResponse.getAttestationCertificate(),
				signedBytes, rawRegisterResponse.getSignature());
		assertTrue(isValid);
	}

	@Test
	public void fullTestSignature() throws DecoderException, SignatureException, JsonMappingException, JsonProcessingException {
		SecurityProviderUtility.installBCProvider();

		String registerResponseString = "{\"registrationData\":\"BQQ6WP62_rMN3B3NpJEHLYeneiFleE6eLhNkCx8j6z2M3_Xq_lgmWOzbL_EfIW2rQgRv49btpoSB6fyuMueTkZb7QCfYxzgdxBC-M4xI_w3eDcG-OydbkimTd0RgF2gBDVv-d-g3syv_erfXEwpSeamWJjB4s4P35pcHBRsZ5hOlJZMwggImMIIBzKADAgECAoGBAPMsD5b5G58AphKuKWl4Yz27sbE_rXFy7nPRqtJ_r4E5DSZbFvfyuos-Db0095ubB0JoyM8ccmSO_eZQ6IekOLPKCR7yC5kes-f7MaxyaphmmD4dEvmuKjF-fRsQP5tQG7zerToto8eIz0XjPaupiZxQXtSHGHHTuPhri2nfoZlrMAoGCCqGSM49BAMCMFwxIDAeBgNVBAMTF0dsdXUgb3hQdXNoMiBVMkYgdjEuMC4wMQ0wCwYDVQQKEwRHbHV1MQ8wDQYDVQQHEwZBdXN0aW4xCzAJBgNVBAgTAlRYMQswCQYDVQQGEwJVUzAeFw0xNjAzMDExODU5NDZaFw0xOTAzMDExODU5NDZaMFwxIDAeBgNVBAMTF0dsdXUgb3hQdXNoMiBVMkYgdjEuMC4wMQ0wCwYDVQQKEwRHbHV1MQ8wDQYDVQQHEwZBdXN0aW4xCzAJBgNVBAgTAlRYMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABICUKnzCE5PJ7tihiKkYu6E5Uy_sZ-RSqs_MnUJt0tB8G8GSg9nKo6P2424iV9lXX9Pil8qw4ofZ-fAXXepbp4MwCgYIKoZIzj0EAwIDSAAwRQIgUWwawAB2udURWQziDXVjSOi_QcuXiRxylqj5thFwFhYCIQCGY-CTZFi7JdkhZ05nDpbSYJBTOo1Etckh7k0qcvnO0TBFAiEA6prZJBVRXpq7vnY126J9zEhEktQvqmIspOGXq74JnQcCIC-o8h-53-WDenYJtYO0obSjCOaLLkM6ejdmiZrTOfC-\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6ImJEcE1nbTVkYmg2cFMzcFdqWkVRZEVQSUpJdXE4ckJwUElUSjRIdG5FWnciLCJvcmlnaW4iOiJodHRwczpcL1wvdTIwNC5qYW5zLmluZm8ifQ\",\"deviceData\":\"eyJuYW1lIjoiU00tRzk5MUIiLCJvc19uYW1lIjoidGlyYW1pc3UiLCJvc192ZXJzaW9uIjoiMTMiLCJwbGF0Zm9ybSI6ImFuZHJvaWQiLCJwdXNoX3Rva2VuIjoiY2dtS21lQk9SbTZBMEJTRFZsOHBxVDpBUEE5MWJHeGRiWnNHTzJqTTUyUnAyM3JMYzNrcUdBY2JNRUI4NmpJdVJoVTJjTEFtS2ZUWExOX01YSVI2bWVNZ09WZVJ5RUVxbGlUejRrdTUxekIwYVMyYnk2MDJZem9tSXJXSnB2SEg5NlgySmxkUFVJbkdqdGIwZmcyQWhyNFNuX3I4SjBwcU55ayIsInR5cGUiOiJub3JtYWwiLCJ1dWlkIjoiZmY4MmZlZTEtMWQ4Yi0zN2RlLWE4ZjItOWFmZjM5NjM2Y2E1In0\"}";
		String authenticateResponseString = "{\"signatureData\":\"AQAAAAEwRQIgeJwFiuvStieJDG_-wJ8c1zrht7HtuRHBpwelD0r2PJUCIQD9i-iLH9yOR-LlOpEpCl2ieyNYEr5SeMi9vrL_gm7QWQ\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiLUhsQ1NiSENreklVdnhGdHQxZWkyZS1qYjVzdVBsQ3ByVDdtalh6clFwRSIsIm9yaWdpbiI6Imh0dHBzOlwvXC91MjA0LmphbnMuaW5mb1wvamFucy1hdXRoXC9kZXZpY2VfYXV0aG9yaXphdGlvbi5odG0ifQ\",\"keyHandle\":\"J9jHOB3EEL4zjEj_Dd4Nwb47J1uSKZN3RGAXaAENW_536DezK_96t9cTClJ5qZYmMHizg_fmlwcFGxnmE6Ulkw\"}";

		RegisterResponse registerResponse = ServerUtil.jsonMapperWithWrapRoot().readValue(registerResponseString, RegisterResponse.class);
        RawRegisterResponse rawRegisterResponse = (new RawRegistrationService()).parseRawRegisterResponse(registerResponse.getRegistrationData());

		SignatureVerification signatureVerification = new SHA256withECDSASignatureVerification();

		// Attestation check
		String appId = "https://u204.jans.info/jans-auth/device_authorization.htm";
		byte[] signedBytes = packBytesToAttestationSign(signatureVerification.hash(appId),
				signatureVerification.hash(registerResponse.getClientData().getChallenge()), rawRegisterResponse.getKeyHandle(),
				rawRegisterResponse.getUserPublicKey());

		boolean isValid = signatureVerification.checkSignature(rawRegisterResponse.getAttestationCertificate(),
				signedBytes, rawRegisterResponse.getSignature());
		assertTrue(isValid);

		// Authentication check
		AuthenticateResponse authenticateResponse = ServerUtil.jsonMapperWithWrapRoot().readValue(authenticateResponseString, AuthenticateResponse.class);
        RawAuthenticateResponse rawAuthenticateResponse = (new RawAuthenticationService()).parseRawAuthenticateResponse(authenticateResponse.getSignatureData());

		byte[] signedBytesAuth = packBytesToAuthenticationSign(signatureVerification.hash(authenticateResponse.getClientData().getOrigin()), rawAuthenticateResponse.getUserPresence(),
				rawAuthenticateResponse.getCounter(), signatureVerification.hash(authenticateResponse.getClientData().getRawClientData()));
	
		boolean isValidAuth = signatureVerification.checkSignature(signatureVerification.decodePublicKey(rawRegisterResponse.getUserPublicKey()), signedBytesAuth, rawAuthenticateResponse.getSignature());
		assertTrue(isValidAuth);
	}
	
	@Test
	public void checkClientDataSignatureVerification() throws DecoderException, SignatureException {
		SecurityProviderUtility.installBCProvider();

		String clientDataHex = "65794a30655841694f694a7559585a705a32463062334975615751755a32563051584e7a5a584a306157397549697769593268686247786c626d646c496a6f694f5659354c56685652475a724e6c64305a453147624459314e3235504e6e4e4756465656635538785157567661465254574842315254647559794973496d39796157647062694936496d68306448427a4f6c7776584339686247786f5957356b637a517a4c6d64736458557562334a6e584339705a47567564476c30655677765958563061474e765a47557561485274496e30";
		byte[] clientData = Hex.decodeHex(clientDataHex);

		String authResponseDataHex = "415141414141677752674968414c4f4f62544e55506677772d643669776c6a6132636f714134473561374f4156534e744b4462513034717341694541684a734542745072494a49766436636e595351454842415549723644395839794e70636c6166544c797749";
		byte[] authResponseData = Hex.decodeHex(authResponseDataHex);

		String publicKeyHex = "04e9a52ef1136d1eee973c700bd86e1dd314dc04373d47f1219d1f8c286c9f30311fdbb158eaceac60e3a7a0298c94269878c5ec6853004182e126cdb72254edc2";
		byte[] publicKey = Hex.decodeHex(publicKeyHex);

		ClientData clientDataObj = new ClientData(new String(clientData));
		RawAuthenticateResponse rawAuthenticateResponse = new RawAuthenticationService()
				.parseRawAuthenticateResponse(new String(authResponseData));

		SignatureVerification signatureVerification = new SHA256withECDSASignatureVerification();

		String appId = "https://allhands43.gluu.org/identity/authcode.htm";
		byte[] signedBytes = packBytesToAuthenticationSign(signatureVerification.hash(appId),
				rawAuthenticateResponse.getUserPresence(), rawAuthenticateResponse.getCounter(),
				signatureVerification.hash(clientDataObj.getRawClientData()));

		boolean isValid = signatureVerification.checkSignature(signatureVerification.decodePublicKey(publicKey),
				signedBytes, rawAuthenticateResponse.getSignature());
		assertTrue(isValid);
	}

	private byte[] packBytesToAttestationSign(byte[] appIdHash, byte[] challengeHash, byte[] keyHandleHash, byte[] userPublicKey) {
		ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
		encoded.write(0x00); // +
		encoded.write(appIdHash); // +
		encoded.write(challengeHash);
		encoded.write(keyHandleHash);
		encoded.write(userPublicKey);

		//byte[] signatureBase = ByteBuffer.allocate(bufferSize).put(reserved).put(rpIdHash).put(clientDataHash).put(credId).put(publicKey).array();

		return encoded.toByteArray();
	}

	private byte[] packBytesToAuthenticationSign(byte[] appIdHash, byte userPresence, long counter, byte[] challengeHash) {
		
		System.out.println(Hex.encodeHex(appIdHash));
		System.out.println(Hex.encodeHex(new byte[] { userPresence }));
		System.out.println(Hex.encodeHex((BigInteger.valueOf(counter)).toByteArray()));
		System.out.println(Hex.encodeHex(challengeHash));

		ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
		encoded.write(appIdHash);
		encoded.write(userPresence);
		encoded.writeInt((int) counter);
		encoded.write(challengeHash);

		return encoded.toByteArray();
	}

	
	public static void main(String[] args) throws DecoderException, SignatureException {
		RawAuthenticationServiceUnitTest test = new RawAuthenticationServiceUnitTest();
		test.checkClientDataSignatureVerification();
	}
}
