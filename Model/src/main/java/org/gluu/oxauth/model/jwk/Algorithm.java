/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.jwk;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.util.StringUtils;
import org.gluu.oxauth.model.crypto.signature.RSAKeyFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Identifies the cryptographic algorithm used with the key.
 *
 * @author Javier Rojas Blum
 * @author Sergey Manoylo
 * @version December 17, 2021
 */
@SuppressWarnings("java:S1874")
public enum Algorithm {

    // Signature
    RS256("RS256", Use.SIGNATURE, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),
    RS384("RS384", Use.SIGNATURE, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),
    RS512("RS512", Use.SIGNATURE, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),
    ES256("ES256", Use.SIGNATURE, AlgorithmFamily.EC, 256),
    ES384("ES384", Use.SIGNATURE, AlgorithmFamily.EC, 384),
    ES512("ES512", Use.SIGNATURE, AlgorithmFamily.EC, 528),
    PS256("PS256", Use.SIGNATURE, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),
    PS384("PS384", Use.SIGNATURE, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),
    PS512("PS512", Use.SIGNATURE, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),

    // Encryption
    RSA1_5("RSA1_5", Use.ENCRYPTION, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH),
    RSA_OAEP("RSA-OAEP", Use.ENCRYPTION, AlgorithmFamily.RSA, RSAKeyFactory.DEF_KEYLENGTH);

    private final String paramName;
    private final Use use;
    private final AlgorithmFamily family;
    private final int keyLength;

    Algorithm(String paramName, Use use, AlgorithmFamily family, int keyLength) {
        this.paramName = paramName;
        this.use = use;
        this.family = family;
        this.keyLength = keyLength;	// bits
    }

    public String getParamName() {
        return paramName;
    }

    public Use getUse() {
        return use;
    }

    public AlgorithmFamily getFamily() {
        return family;
    }

    public int getKeyLength() {
        return keyLength;
    }

    /**
     * Returns the corresponding {@link Algorithm} for a parameter.
     *
     * @param param The use parameter.
     * @return The corresponding algorithm if found, otherwise <code>null</code>.
     */
    @JsonCreator
    public static Algorithm fromString(String param) {
        if (param != null) {
            for (Algorithm algorithm : Algorithm.values()) {
                if (param.equals(algorithm.paramName)) {
                    return algorithm;
                }
            }
        }
        return null;
    }

    public static List<Algorithm> fromString(String[] params, Use use) {
        List<Algorithm> algorithms = new ArrayList<Algorithm>();

        for (String param : params) {
            Algorithm algorithm = Algorithm.fromString(param);
            if (algorithm != null && algorithm.use == use) {
                algorithms.add(algorithm);
            } else if (StringUtils.equals("RSA_OAEP", param)) {
                algorithms.add(RSA_OAEP);
            }
        }

        return algorithms;
    }


    /**
     * Returns a string representation of the object. In this case the parameter name.
     *
     * @return The string representation of the object.
     */
    @Override
    @JsonValue
    public String toString() {
        return paramName;
    }
}