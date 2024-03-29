/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.cert.fingerprint;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility which help to calculate SSH RSA public key fingerprint
 * 
 * @author Yuriy Movchan
 * @version March 03, 2016
 */
public class FingerprintHelper {

    @SuppressWarnings("unused")
    private static final Logger log = LoggerFactory.getLogger(FingerprintHelper.class);

    /*
     * Return SSH RSA public key fingerprint
     */
    @SuppressWarnings("java:S4790")
    public static String getPublicKeySshFingerprint(PublicKey publicKey) throws NoSuchAlgorithmException, IOException {
    if (publicKey instanceof RSAPublicKey || publicKey instanceof ECPublicKey) {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] derEncoded = null;                
            if(publicKey instanceof RSAPublicKey) {
                derEncoded = getDerEncoding((RSAPublicKey)publicKey);
            }
            else if (publicKey instanceof ECPublicKey) {
                derEncoded = getDerEncoding((ECPublicKey)publicKey);
            }
            byte[] fingerprint = digest.digest(derEncoded);
            return Hex.encodeHexString(fingerprint);
        }
        throw new NoSuchAlgorithmException("Unsopported PublicKey type");
    }

    private static byte[] getDerEncoding(RSAPublicKey key) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(buffer);
        writeDataWithLength("ssh-rsa".getBytes(), dataOutput);
        writeDataWithLength(key.getPublicExponent().toByteArray(), dataOutput);
        writeDataWithLength(key.getModulus().toByteArray(), dataOutput);
        return buffer.toByteArray();
    }

    /* 
     * here is a pseudo SSH encoding (start string is 'ssh-ecdsa'), as format of SSH for EC something like that:
     *    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCzhFSVzzMlfUih30HB8k7Dpmn95NWQMQRcYpHWhIcMsXQL7TFD8izlr0bRA9XTmBDyKhgA80XMr33r4jeiP+MI=
     * or for EDDSA (ed25519) 
     *    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFPZ6PEne43qIHzRihLo4wbo9+E7IFgPp7HLYLFoDiXz
     * but current encoding is enough for generating a unique fingerprint.
     */
    private static byte[] getDerEncoding(ECPublicKey key) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(buffer);
        writeDataWithLength("ssh-ecdsa".getBytes(), dataOutput);
        writeDataWithLength(key.getEncoded(), dataOutput);
        return buffer.toByteArray();
    }

    private static void writeDataWithLength(byte[] data, DataOutput byteBuffer) throws IOException {
        byteBuffer.writeInt(data.length);
        byteBuffer.write(data);
    }

}
