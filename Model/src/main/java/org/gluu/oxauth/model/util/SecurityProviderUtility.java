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

			log.info("fipsMode - "+fipsMode);
			if (fipsMode) {
				bouncyCastleProvider = (BouncyCastleFipsProvider) Security
						.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);
				if (bouncyCastleProvider == null) {
					bouncyCastleProvider = new BouncyCastleFipsProvider();
					Security.addProvider(bouncyCastleProvider);
				}
			} else {
				log.info("In else");
				//bouncyCastleProvider = (BouncyCastleProvider) Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
				//if (bouncyCastleProvider == null) {
				//	bouncyCastleProvider = new BouncyCastleProvider();
				//	Security.addProvider(bouncyCastleProvider);
				//}
			}

		}

		return bouncyCastleProvider;
	}

	public static boolean hasFipsMode() {
		return fipsMode;
	}

}