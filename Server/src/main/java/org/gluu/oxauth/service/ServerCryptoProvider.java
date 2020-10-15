package org.gluu.oxauth.service;

import org.apache.log4j.Logger;
import org.gluu.oxauth.model.config.ConfigurationFactory;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.crypto.signature.AlgorithmFamily;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.service.cdi.util.CdiUtil;
import org.json.JSONObject;
import org.msgpack.core.Preconditions;

import java.security.KeyStoreException;
import java.security.PrivateKey;

/**
 * @author Yuriy Zabrovarnyy
 */
public class ServerCryptoProvider extends AbstractCryptoProvider {

    private static final Logger LOG = Logger.getLogger(ServerCryptoProvider.class);

    private final ConfigurationFactory configurationFactory;
    private final AbstractCryptoProvider cryptoProvider;

    public ServerCryptoProvider(AbstractCryptoProvider cryptoProvider) {
        this.configurationFactory = CdiUtil.bean(ConfigurationFactory.class);
        this.cryptoProvider = cryptoProvider;
        Preconditions.checkNotNull(configurationFactory);
        Preconditions.checkNotNull(cryptoProvider);
    }

    @Override
    public String getKeyId(JSONWebKeySet jsonWebKeySet, Algorithm algorithm, Use use) throws Exception {
        try {
            if (algorithm == null || AlgorithmFamily.HMAC.equals(algorithm.getFamily())) {
                return null;
            }
            final String kid = cryptoProvider.getKeyId(jsonWebKeySet, algorithm, use);
            if (!cryptoProvider.getKeys().contains(kid) && configurationFactory.reloadConfFromLdap()) {
                return cryptoProvider.getKeyId(jsonWebKeySet, algorithm, use);
            }
            return kid;

        } catch (KeyStoreException e) {
            LOG.trace("Try to re-load configuration due to keystore exception (it can be rotated).");
            if (configurationFactory.reloadConfFromLdap()) {
                return cryptoProvider.getKeyId(jsonWebKeySet, algorithm, use);
            }
        }
        return null;
    }

    @Override
    public JSONObject generateKey(Algorithm algorithm, Long expirationTime, Use use) throws Exception {
        return cryptoProvider.generateKey(algorithm, expirationTime, use);
    }

    @Override
    public String sign(String signingInput, String keyId, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        if (configurationFactory.getAppConfiguration().getRejectJwtWithNoneAlg() && signatureAlgorithm == SignatureAlgorithm.NONE) {
            throw new UnsupportedOperationException("None algorithm is forbidden by `rejectJwtWithNoneAlg` configuration property.");
        }
        return cryptoProvider.sign(signingInput, keyId, sharedSecret, signatureAlgorithm);
    }

    @Override
    public boolean verifySignature(String signingInput, String encodedSignature, String keyId, JSONObject jwks, String sharedSecret, SignatureAlgorithm signatureAlgorithm) throws Exception {
        if (configurationFactory.getAppConfiguration().getRejectJwtWithNoneAlg() && signatureAlgorithm == SignatureAlgorithm.NONE) {
            LOG.trace("None algorithm is forbidden by `rejectJwtWithNoneAlg` configuration property.");
            return false;
        }
        return cryptoProvider.verifySignature(signingInput, encodedSignature, keyId, jwks, sharedSecret, signatureAlgorithm);
    }

    @Override
    public boolean deleteKey(String keyId) throws Exception {
        return cryptoProvider.deleteKey(keyId);
    }

    @Override
    public boolean containsKey(String keyId) {
        return cryptoProvider.containsKey(keyId);
    }

    @Override
    public PrivateKey getPrivateKey(String keyId) throws Exception {
        return cryptoProvider.getPrivateKey(keyId);
    }
}
