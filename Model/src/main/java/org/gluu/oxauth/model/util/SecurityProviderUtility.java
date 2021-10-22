/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.util;

import java.io.File;
import java.io.FileInputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

/**
 * @author madhumitas
 *
 */
public class SecurityProviderUtility {

	private static final Logger log = Logger.getLogger(JwtUtil.class);

	private static boolean fipsMode = false;

	private static final String BASE_DIR;

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

	public static Provider getInstance(boolean silent) {
		String className = "org.bouncycastle.jce.provider.BouncyCastleProvider";
		String providerName = "BC";
		if (!fipsMode) {
			String propertiesFile = BASE_PROPERTIES_FILE;
			FileInputStream conf = null;
			try {
				conf = new FileInputStream(propertiesFile);
				Properties prop;
				prop = new Properties();
				prop.load(conf);
				if (Boolean.valueOf(prop.getProperty("fipsMode")) == true) {
					fipsMode = true;
				}
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			} finally {
				IOUtils.closeQuietly(conf);
			}
		}
		log.info("fipsMode - " + fipsMode);

		if (fipsMode) {

			className = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
			providerName = "BCFIPS";
		}
		Class<?> bouncyCastleProviderClass;
		try {
			bouncyCastleProviderClass = Class.forName(className);
			if (bouncyCastleProvider == null) {
				bouncyCastleProvider = (Provider) bouncyCastleProviderClass.newInstance();
				Security.addProvider(bouncyCastleProvider);
			}
		} catch (ClassNotFoundException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
		} catch (InstantiationException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
		} catch (IllegalAccessException e) {
			log.error(
					"CLass loader doesnt contain correct jars. Please fix it by deploying the war with correct parameters");
			log.error(e.getMessage(), e);
		}
		bouncyCastleProvider = Security.getProvider(providerName);

		return bouncyCastleProvider;

	}

	public static boolean hasFipsMode() {
		return fipsMode;
	}

}