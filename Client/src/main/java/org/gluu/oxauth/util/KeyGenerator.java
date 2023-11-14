/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.util;

import static org.gluu.oxauth.model.jwk.JWKParameter.CERTIFICATE_CHAIN;
import static org.gluu.oxauth.model.jwk.JWKParameter.EXPIRATION_TIME;
import static org.gluu.oxauth.model.jwk.JWKParameter.EXPONENT;
import static org.gluu.oxauth.model.jwk.JWKParameter.KEY_ID;
import static org.gluu.oxauth.model.jwk.JWKParameter.MODULUS;
import static org.gluu.oxauth.model.jwk.JWKParameter.X;
import static org.gluu.oxauth.model.jwk.JWKParameter.Y;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.status.StatusLogger;
import org.gluu.oxauth.model.crypto.AbstractCryptoProvider;
import org.gluu.oxauth.model.crypto.OxAuthCryptoProvider;
import org.gluu.oxauth.model.crypto.OxElevenCryptoProvider;
import org.gluu.oxauth.model.crypto.encryption.KeyEncryptionAlgorithm;
import org.gluu.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.gluu.oxauth.model.jwk.Algorithm;
import org.gluu.oxauth.model.jwk.JSONWebKey;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;
import org.gluu.oxauth.model.jwk.KeyType;
import org.gluu.oxauth.model.jwk.Use;
import org.gluu.util.security.SecurityProviderUtility;
import org.gluu.oxauth.model.util.StringUtils;
import org.gluu.util.StringHelper;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Command example:
 * java -cp bcprov-jdk18on-1.54.jar:.jar:bcpkix-jdk18on-1.54.jar:commons-cli-1.2.jar:commons-codec-1.5.jar:commons-lang-2.6.jar:jettison-1.3.jar:log4j-1.2.14.jar:oxauth-model.jar:oxauth.jar org.gluu.oxauth.util.KeyGenerator -h
 * <p/>
 * KeyGenerator -sig_keys RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 -enc_keys RSA_OAEP RSA1_5 -keystore /Users/JAVIER/tmp/mykeystore.jks -keypasswd secret -dnname "CN=oxAuth CA Certificates" -expiration 365
 * <p/>
 * KeyGenerator -sig_keys RS256 RS384 RS512 ES256 ES384 ES512 -ox11 https://ce.gluu.info:8443/oxeleven/rest/generateKey -expiration 365 -at xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 *
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version February 12, 2019
 */
public class KeyGenerator {

    private static final String SIGNING_KEYS = "sig_keys";
    private static final String ENCRYPTION_KEYS = "enc_keys";
    private static final String KEY_STORE_FILE = "keystore";
    private static final String KEY_STORE_PASSWORD = "keypasswd";
    private static final String DN_NAME = "dnname";
    private static final String OXELEVEN_ACCESS_TOKEN = "at";
    private static final String OXELEVEN_GENERATE_KEY_ENDPOINT = "ox11";
    private static final String EXPIRATION = "expiration";
    private static final String EXPIRATION_HOURS = "expiration_hours";
    private static final String KEY_LENGTH = "key_length";
    private static final String KEY_STORE_FILE_TYPE = "keystore_type";
    private static final String HELP = "h";
    private static final Logger log;

    static {
        StatusLogger.getLogger().setLevel(Level.OFF);
        log = Logger.getLogger(KeyGenerator.class);
    }

    public static void main(String[] args) throws Exception {
        new Cli(args).parse();
    }

    public static class Cli {
        private String[] args = null;
        private Options options = new Options();

        public Cli(String[] args) {
            this.args = args;

            Option signingKeysOption = new Option(SIGNING_KEYS, true,
                    "Signature keys to generate. (RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512).");
            signingKeysOption.setArgs(Option.UNLIMITED_VALUES);

            Option encryptionKeysOption = new Option(ENCRYPTION_KEYS, true,
                    "Encryption keys to generate. (RSA_OAEP RSA1_5).");
            encryptionKeysOption.setArgs(Option.UNLIMITED_VALUES);

            options.addOption(signingKeysOption);
            options.addOption(encryptionKeysOption);
            options.addOption(KEY_STORE_FILE, true, "Key Store file.");
            options.addOption(KEY_STORE_PASSWORD, true, "Key Store password.");
            options.addOption(DN_NAME, true, "DN of certificate issuer.");
            options.addOption(OXELEVEN_ACCESS_TOKEN, true, "oxEleven Access Token");
            options.addOption(OXELEVEN_GENERATE_KEY_ENDPOINT, true, "oxEleven Generate Key Endpoint.");
            options.addOption(EXPIRATION, true, "Expiration in days.");
            options.addOption(EXPIRATION_HOURS, true, "Expiration in hours.");
            options.addOption(KEY_LENGTH, true, "Key length");
            options.addOption(KEY_STORE_FILE_TYPE, true, "Key Store type");
            options.addOption(HELP, false, "Show help.");
       }

        public void parse() {
            CommandLineParser parser = new BasicParser();

            CommandLine cmd = null;
            try {
                cmd = parser.parse(options, args);

                if (cmd.hasOption(HELP)) {
                    help();
                }

                if (!((cmd.hasOption(SIGNING_KEYS) || cmd.hasOption(ENCRYPTION_KEYS))
                        && (cmd.hasOption(EXPIRATION) || cmd.hasOption(EXPIRATION_HOURS)))) {
                    help();
                }

                String[] sigAlgorithms = cmd.getOptionValues(SIGNING_KEYS);
                String[] encAlgorithms = cmd.getOptionValues(ENCRYPTION_KEYS);
                List<Algorithm> signatureAlgorithms = cmd.hasOption(SIGNING_KEYS) ? Algorithm.fromString(sigAlgorithms, Use.SIGNATURE) : new ArrayList<Algorithm>();
                List<Algorithm> encryptionAlgorithms = cmd.hasOption(ENCRYPTION_KEYS) ? Algorithm.fromString(encAlgorithms, Use.ENCRYPTION) : new ArrayList<Algorithm>();
                if (signatureAlgorithms.isEmpty() && encryptionAlgorithms.isEmpty()) {
                    help();
                }

                int keyLength = StringHelper.toInt(cmd.getOptionValue(KEY_LENGTH), 2048);
                int expiration = StringHelper.toInt(cmd.getOptionValue(EXPIRATION), 0);
                int expiration_hours = StringHelper.toInt(cmd.getOptionValue(EXPIRATION_HOURS), 0);

                if(cmd.hasOption(KEY_STORE_FILE_TYPE)) {
                    String keyStoreFileType = cmd.getOptionValue(KEY_STORE_FILE_TYPE);
                    SecurityProviderUtility.KeyStorageType keyStorageType = SecurityProviderUtility.KeyStorageType.fromString(keyStoreFileType);
                    if (keyStorageType == null) {
                        throw new ParseException(String.format("Wrong option =  %s value = %s", KEY_STORE_FILE_TYPE, keyStoreFileType));
                    }
                    SecurityProviderUtility.SecurityModeType securityMode = keyStorageType.getSecurityMode();
                    SecurityProviderUtility.setSecurityMode(securityMode);
                }

                if (cmd.hasOption(OXELEVEN_ACCESS_TOKEN) && cmd.hasOption(OXELEVEN_GENERATE_KEY_ENDPOINT)) {
                    String accessToken = cmd.getOptionValue(OXELEVEN_ACCESS_TOKEN);
                    String generateKeyEndpoint = cmd.getOptionValue(OXELEVEN_GENERATE_KEY_ENDPOINT);

                    try {
                        OxElevenCryptoProvider cryptoProvider = new OxElevenCryptoProvider(generateKeyEndpoint,
                                null, null, null, accessToken);

                        generateKeys(cryptoProvider, signatureAlgorithms, encryptionAlgorithms, expiration, expiration_hours, keyLength);
                    } catch (Exception e) {
                        log.error("Failed to generate keys", e);
                        help();
                    }
                } else if (cmd.hasOption(KEY_STORE_FILE)
                        && cmd.hasOption(KEY_STORE_PASSWORD)
                        && cmd.hasOption(DN_NAME)) {
                    String keystore = cmd.getOptionValue(KEY_STORE_FILE);
                    String keypasswd = cmd.getOptionValue(KEY_STORE_PASSWORD);
                    String dnName = cmd.getOptionValue(DN_NAME);

                    try {
                        SecurityProviderUtility.installBCProvider(true);

                        OxAuthCryptoProvider cryptoProvider = new OxAuthCryptoProvider(keystore, keypasswd, dnName);
                        generateKeys(cryptoProvider, signatureAlgorithms, encryptionAlgorithms, expiration, expiration_hours, keyLength);
                    } catch (Exception e) {
                        e.printStackTrace();
                        log.error("Failed to generate keys", e);
                        help();
                    }
                } else {
                    help();
                }
            } catch (ParseException e) {
                log.error("Failed to generate keys", e);
                help();
            }
        }

		private void generateKeys(AbstractCryptoProvider cryptoProvider, List<Algorithm> signatureAlgorithms,
				List<Algorithm> encryptionAlgorithms, int expiration, int expiration_hours, int keyLength) throws Exception {
			JSONWebKeySet jwks = new JSONWebKeySet();

			Calendar calendar = new GregorianCalendar();
			calendar.add(Calendar.DATE, expiration);
			calendar.add(Calendar.HOUR, expiration_hours);

			for (Algorithm algorithm : signatureAlgorithms) {
				SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.name());
				JSONObject result = cryptoProvider.generateKey(algorithm, calendar.getTimeInMillis(), Use.SIGNATURE, keyLength);

				JSONWebKey key = new JSONWebKey();
				key.setKid(result.getString(KEY_ID));
				key.setUse(Use.SIGNATURE);
				key.setAlg(algorithm);
				key.setKty(KeyType.fromString(signatureAlgorithm.getFamily().toString()));
				key.setExp(result.optLong(EXPIRATION_TIME));
				key.setCrv(signatureAlgorithm.getCurve());
				key.setN(result.optString(MODULUS));
				key.setE(result.optString(EXPONENT));
				key.setX(result.optString(X));
				key.setY(result.optString(Y));

				JSONArray x5c = result.optJSONArray(CERTIFICATE_CHAIN);
				key.setX5c(StringUtils.toList(x5c));

				jwks.getKeys().add(key);
			}

			for (Algorithm algorithm : encryptionAlgorithms) {
			    KeyEncryptionAlgorithm encryptionAlgorithm = KeyEncryptionAlgorithm.fromName(algorithm.getParamName());
			    JSONObject result = cryptoProvider.generateKey(algorithm, calendar.getTimeInMillis(), Use.ENCRYPTION, keyLength);

			    JSONWebKey key = new JSONWebKey();
			    key.setKid(result.getString(KEY_ID));
			    key.setUse(Use.ENCRYPTION);
			    key.setAlg(algorithm);
			    key.setKty(KeyType.fromString(encryptionAlgorithm.getFamily()));
			    key.setExp(result.optLong(EXPIRATION_TIME));
			    key.setN(result.optString(MODULUS));
			    key.setE(result.optString(EXPONENT));
			    key.setX(result.optString(X));
			    key.setY(result.optString(Y));

			    JSONArray x5c = result.optJSONArray(CERTIFICATE_CHAIN);
			    key.setX5c(StringUtils.toList(x5c));

			    jwks.getKeys().add(key);
			}

			System.out.println(jwks);
		}

        private void help() {
            HelpFormatter formatter = new HelpFormatter();

            formatter.printHelp(
                    "KeyGenerator -sig_keys alg ... -enc_keys alg ... -expiration n_days [-expiration_hours n_hours] [-ox11 url] [-keystore path -keystore_type ks_type -keypasswd secret -dnname dn_name]",
                    options);
            System.exit(0);
        }
    }
}