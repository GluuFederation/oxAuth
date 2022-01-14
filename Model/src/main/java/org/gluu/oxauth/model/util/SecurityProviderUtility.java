/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.status.StatusLogger;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author madhumitas
 *
 */
public class SecurityProviderUtility {

	private static final Logger log ;

	private static boolean fipsMode = false;

	private static final String BASE_DIR;

	static {
		StatusLogger.getLogger().setLevel(Level.ALL);
		log = Logger.getLogger(SecurityProviderUtility.class);
	}
	
	private static Provider bouncyCastleProvider;
	static {
		if (System.getProperty("gluu.base") != null) {
			BASE_DIR = System.getProperty("gluu.base");
		} else if ((System.getProperty("catalina.base") != null)
				&& (System.getProperty("catalina.base.ignore") == null)) {
			BASE_DIR = System.getProperty("catalina.base");
		} else if (System.getProperty("catalina.home") != null) {
			BASE_DIR = System.getProperty("catalina.home");
		} else if (System.getProperty("jboss.home.dir") != null) {
			BASE_DIR = System.getProperty("jboss.home.dir");
		} else {
			BASE_DIR = null;
		}
	}
	private static final String DIR = BASE_DIR + File.separator + "conf" + File.separator;
	private static final String BASE_PROPERTIES_FILE = DIR + "gluu.properties";

	public static Provider getBCProvider(boolean silent) {
		String className = "org.bouncycastle.jce.provider.BouncyCastleProvider";
		String providerName = "BC";
		
		fipsMode = checkFipsMode();
		log.info("fipsMode - " + fipsMode);
		System.out.println("fipsMode - " + fipsMode);
		if (fipsMode) {

			className = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
			providerName = "BCFIPS";
		}
		Class<?> bouncyCastleProviderClass;
		
		try {
			bouncyCastleProvider = (Provider) Class.forName(className).getConstructor().newInstance();
			
			
			 Security.addProvider(bouncyCastleProvider);
			/*
			 * bouncyCastleProviderClass = Class.forName(className); if
			 * (bouncyCastleProvider == null) { bouncyCastleProvider = (Provider)
			 * Class.forName(className).getConstructor(Provider.class).newInstance();
			 * //bouncyCastleProvider = bouncyCastleProvider = (Provider)
			 * bouncyCastleProviderClass.newInstance();
			 * Security.addProvider(bouncyCastleProvider); }
			 */
		} catch (IllegalArgumentException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		}   catch (SecurityException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		} catch (InstantiationException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
			e.printStackTrace();
		}
		bouncyCastleProvider = Security.getProvider(providerName);

		return bouncyCastleProvider;

	}

	public static String getBCProviderName() {
		return bouncyCastleProvider.getName();
	}

	public static boolean hasFipsMode() {
		return fipsMode;
	}

	/**
	 * A check that the server is running in FIPS-approved-only mode. This is a part
	 * of compliance to ensure that the server is really FIPS compliant
	 * 
	 * @return
	 */
	private static boolean checkFipsMode() {

		try {
			Process process = Runtime.getRuntime().exec("fips-mode-setup --check");

			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

			String line = null;
			while ((line = reader.readLine()) != null) {
				if (line.equalsIgnoreCase("FIPS mode is enabled.")) {
					return true;
				}
			}

		} catch (IOException e) {
			log.error(e.getMessage(), e);
			return false;
		}

		return false;
	}

	public static void main(String a[]) throws NoSuchAlgorithmException
	{
		System.out.println("main");
		SecurityProviderUtility.getBCProvider(false);
		
		 // Security.setProperty("crypto.policy", "limited"); // uncomment to switch to limited crypto policies
        System.out.println("Check for unlimited crypto policies");
        System.out.println("Java version: " + Runtime.version());
        //Security.setProperty("crypto.policy", "limited"); // muss ganz am anfang gesetzt werden !
        System.out.println("restricted cryptography: " + restrictedCryptography() + " Notice: 'false' means unlimited policies"); // false mean unlimited crypto
        System.out.println("Security properties: " + Security.getProperty("crypto.policy"));
        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max AES key length = " + maxKeyLen);
    }

    /**
     * Determines if cryptography restrictions apply.
     * Restrictions apply if the value of {@link Cipher#getMaxAllowedKeyLength(String)} returns a value smaller than {@link Integer#MAX_VALUE} if there are any restrictions according to the JavaDoc of the method.
     * This method is used with the transform <code>"AES/CBC/PKCS5Padding"</code> as this is an often used algorithm that is <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl">an implementation requirement for Java SE</a>.
     *
     * @return <code>true</code> if restrictions apply, <code>false</code> otherwise
     * https://stackoverflow.com/posts/33849265/edit, author Maarten Bodewes
     */
    public static boolean restrictedCryptography() {
        try {
            return Cipher.getMaxAllowedKeyLength("AES/CBC/PKCS5Padding") < Integer.MAX_VALUE;
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("The transform \"AES/CBC/PKCS5Padding\" is not available (the availability of this algorithm is mandatory for Java SE implementations)", e);
        }
    }

	
}