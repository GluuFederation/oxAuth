/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.util;

import java.security.Security;

import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * @author madhumitas
 *
 */
public class SecurityProviderUtility {

	private static final Logger log = Logger.getLogger(JwtUtil.class);

	private static BouncyCastleFipsProvider bouncyCastleFipsProvider;

	public static void installBCProvider(boolean silent) {
		bouncyCastleFipsProvider = (BouncyCastleFipsProvider) Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);
		if (bouncyCastleFipsProvider == null) {
			if (!silent) {
				log.info("Adding Bouncy Castle FIPS Provider");
			}

			bouncyCastleFipsProvider = new BouncyCastleFipsProvider();
			Security.addProvider(bouncyCastleFipsProvider);
		} else {
			if (!silent) {
				log.info("Bouncy Castle FIPS Provider was added already");
			}
		}
	}

	public static void installBCProvider() {
		installBCProvider(false);
	}

	public static BouncyCastleFipsProvider getInstance() {
		return bouncyCastleFipsProvider;

	}

}
