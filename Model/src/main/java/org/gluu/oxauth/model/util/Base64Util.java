/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import org.apache.commons.codec.binary.Base64;

/**
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version December 17, 2021 
 */
public class Base64Util {

    public static String base64urlencode(byte[] arg) {
        String s = Base64.encodeBase64String(arg); // Standard base64 encoder
        s = s.split("=")[0]; // Remove any trailing '='s
        s = s.replace('+', '-'); // 62nd char of encoding
        s = s.replace('/', '_'); // 63rd char of encoding
        return s;
    }

    public static byte[] base64urldecode(String arg) throws IllegalArgumentException {
        String s = removePadding(arg);
        return Base64.decodeBase64(s); // Standard base64 decoder
    }

    public static String base64urldecodeToString(String arg) throws IllegalArgumentException, UnsupportedEncodingException {
        byte[] decoded = base64urldecode(arg);
        return new String(decoded, "UTF-8");
    }

    public static String removePadding(String base64UrlEncoded) {
		String s = base64UrlEncoded;
        s = s.replace('-', '+'); // 62nd char of encoding
        s = s.replace('_', '/'); // 63rd char of encoding
        switch (s.length() % 4) // Pad with trailing '='s
        {
            case 0:
                break; // No pad chars in this case
            case 2:
                s += "==";
                break; // Two pad chars
            case 3:
                s += "=";
                break; // One pad char
            default:
                throw new IllegalArgumentException("Illegal base64url string.");
        }
		return s;
	}

    public static String base64urlencodeUnsignedBigInt(final BigInteger bigInteger) {
        return Base64Util.base64urlencode(bigIntegerToUnsignedByteArray(bigInteger));
    }

    public static byte[] unsignedToBytes(int[] plaintextUnsignedBytes) {
        byte[] bytes = new byte[plaintextUnsignedBytes.length];

        for (int i = 0; i < plaintextUnsignedBytes.length; i++) {
            bytes[i] = (byte) plaintextUnsignedBytes[i];
        }

        return bytes;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes) {
            result.append(String.format("%02x", aByte));
        }
        return result.toString();
    }

    public static byte[] bigIntegerToUnsignedByteArray(final BigInteger bigInteger) {
        byte[] array = bigInteger.toByteArray();
        if (array[0] == 0) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        return array; 
    }
}