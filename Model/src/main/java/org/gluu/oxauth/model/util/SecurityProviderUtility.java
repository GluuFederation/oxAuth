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
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

		if (bouncyCastleProvider == null) {
			// determine if the deployment is in an environment where FIPS-mode has been
			// enabled.
			String propertiesFile = BASE_PROPERTIES_FILE;
			FileInputStream conf = null;
			try {
				conf = new FileInputStream(propertiesFile);
				Properties prop;
				prop = new Properties();
				prop.load(conf);
				if (Boolean.valueOf(prop.getProperty("fipsMode")) == true) {
					bouncyCastleProvider = (BouncyCastleFipsProvider) Security
							.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);
					log.info("FipsStatus: " + FipsStatus.isReady());
					log.info("FIPS Status Message: " + FipsStatus.getStatusMessage());
					// this additional flag is needed because during runtime, an instanceOf operator
					// to determine which BC library to use will not be useful given that the
					// existence of the BouncyCastleFipsProvider and BouncyCastleProvider is
					// mutually exclusive
					fipsMode = true;
				} else {
					bouncyCastleProvider = (BouncyCastleProvider) Security
							.getProvider(BouncyCastleProvider.PROVIDER_NAME);
				}
				Security.addProvider(bouncyCastleProvider);
			} catch (Exception e) {
				log.error("Failed to load - " + BASE_PROPERTIES_FILE, e);
			} finally {
				IOUtils.closeQuietly(conf);
			}
			if (!silent) {
				log.info("Adding Bouncy Castle FIPS Provider" + bouncyCastleProvider.getName());
			}

		} else {
			if (!silent) {
				log.info("Bouncy Castle FIPS Provider was added already" + bouncyCastleProvider.getName());
			}
		}

		return bouncyCastleProvider;
	}

	public static boolean hasFipsMode() {
		return fipsMode;
	}

}