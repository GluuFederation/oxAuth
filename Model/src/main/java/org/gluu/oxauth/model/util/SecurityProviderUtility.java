/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.util;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provider installation utility
 *
 * @author Yuriy Movchan
 * @author madhumitas
 */
public class SecurityProviderUtility {

	private static final Logger LOG = LoggerFactory.getLogger(SecurityProviderUtility.class);

	private static boolean isFipsMode = false;

	private static Provider bouncyCastleProvider;

	private static final String BC_GENERIC_PROVIDER_CLASS_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";
	private static final String BC_FIPS_PROVIDER_CLASS_NAME    = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";

	public static void installBCProvider(boolean silent) {
		String providerName = BouncyCastleProvider.PROVIDER_NAME;
		String className = BC_GENERIC_PROVIDER_CLASS_NAME;

		isFipsMode = checkFipsMode();
		if (isFipsMode) {
			LOG.info("Fips mode is enabled");

			providerName = BouncyCastleFipsProvider.PROVIDER_NAME;
			className = BC_FIPS_PROVIDER_CLASS_NAME;
		}

//		// Remove current providers in case on web container restart 
//		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
//		Security.removeProvider(BouncyCastleFipsProvider.PROVIDER_NAME);
		
		try {
			installBCProvider(providerName, className, silent);
		} catch (Exception e) {
			LOG.error(
					"Security provider '{}' doesn't exists in class path. Please deploy correct war for this environment!");
			LOG.error(e.getMessage(), e);
		}
	}

	public static void installBCProvider(String providerName, String providerClassName, boolean silent) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException, ClassNotFoundException {
		bouncyCastleProvider = Security.getProvider(providerName);
		if (bouncyCastleProvider == null) {
			if (!silent) {
				LOG.info("Adding Bouncy Castle Provider");
			}

			bouncyCastleProvider = (Provider) Class.forName(providerClassName).getConstructor().newInstance();
			Security.addProvider(bouncyCastleProvider);
			LOG.info("Provider '{}' with version {} is added", bouncyCastleProvider.getName(), bouncyCastleProvider.getVersionStr());
		} else {
			if (!silent) {
				LOG.info("Bouncy Castle Provider was added already");
			}
		}
	}

	/**
	 * A check that the server is running in FIPS-approved-only mode. This is a part
	 * of compliance to ensure that the server is really FIPS compliant
	 * 
	 * @return boolean value
	 */
	private static boolean checkFipsMode() {
		try {
			// First check if there are FIPS provider libs
			Class.forName(BC_FIPS_PROVIDER_CLASS_NAME);
		} catch (ClassNotFoundException e) {
			LOG.trace("BC Fips provider is not available", e);
			return false;
		}

		try {
			// Check if FIPS is enabled 
			Process process = Runtime.getRuntime().exec("fips-mode-setup --check");
			List<String> result = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
			if ((result.size() > 0) && StringHelper.equalsIgnoreCase(result.get(0), "FIPS mode is enabled.")) {
				return true;
			}
		} catch (IOException e) {
			LOG.error("Failed to check if FIPS mode was enabled", e);
			return false;
		}

		return false;
	}

    /**
     * Determines if cryptography restrictions apply.
     * Restrictions apply if the value of {@link Cipher#getMaxAllowedKeyLength(String)} returns a value smaller than {@link Integer#MAX_VALUE} if there are any restrictions according to the JavaDoc of the method.
     * This method is used with the transform <code>"AES/CBC/PKCS5Padding"</code> as this is an often used algorithm that is <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl">an implementation requirement for Java SE</a>.
     *
     * @return <code>true</code> if restrictions apply, <code>false</code> otherwise
     * https://stackoverflow.com/posts/33849265/edit, author Maarten Bodewes
     */
    public static boolean checkRestrictedCryptography() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES/CBC/PKCS5Padding") < Integer.MAX_VALUE;
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("The transform \"AES/CBC/PKCS5Padding\" is not available (the availability of this algorithm is mandatory for Java SE implementations)", e);
        }
    }

	public static String getBCProviderName() {
		return bouncyCastleProvider.getName();
	}

	public static Provider getBCProvider() {
		return bouncyCastleProvider;
	}

	public static boolean isFipsMode() {
		return isFipsMode;
	}

}