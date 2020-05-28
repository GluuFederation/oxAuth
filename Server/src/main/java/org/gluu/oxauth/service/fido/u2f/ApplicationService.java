/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.fido.u2f;

import java.net.URI;
import java.net.URISyntaxException;

import javax.ejb.Stateless;
import javax.inject.Named;

import org.gluu.net.InetAddressUtility;
import org.gluu.oxauth.exception.fido.u2f.BadConfigurationException;

/**
 * Provides operations with U2F applications
 *
 * @author Yuriy Movchan Date: 05/19/2015
 */
@Stateless
@Named
public class ApplicationService {

	private boolean validateApplication = true;

	public boolean isValidateApplication() {
		return validateApplication;
	}

	/**
	 * Throws {@link BadConfigurationException} if the given App ID is found to
	 * be incompatible with the U2F specification or any major U2F Client
	 * implementation.
	 *
	 * @param appId
	 *            the App ID to be validated
	 */
	public void checkIsValid(String appId) {
		if (!appId.contains(":")) {
			throw new BadConfigurationException("App ID does not look like a valid facet or URL. Web facets must start with 'https://'.");
		}

		if (appId.startsWith("http:")) {
			throw new BadConfigurationException("HTTP is not supported for App IDs. Use HTTPS instead.");
		}

		if (appId.startsWith("https://")) {
			URI url = checkValidUrl(appId);
			checkPathIsNotSlash(url);
//			checkNotIpAddress(url);
		}
	}

	private void checkPathIsNotSlash(URI url) {
		if ("/".equals(url.getPath())) {
			throw new BadConfigurationException(
					"The path of the URL set as App ID is '/'. This is probably not what you want -- remove the trailing slash of the App ID URL.");
		}
	}

	private URI checkValidUrl(String appId) {
		URI url = null;
		try {
			url = new URI(appId);
		} catch (URISyntaxException e) {
			throw new BadConfigurationException("App ID looks like a HTTPS URL, but has syntax errors.", e);
		}
		return url;
	}

	private void checkNotIpAddress(URI url) {
		if (InetAddressUtility.isIpAddress(url.getAuthority()) || (url.getHost() != null && InetAddressUtility.isIpAddress(url.getHost()))) {
			throw new BadConfigurationException("App ID must not be an IP-address, since it is not supported. Use a host name instead.");
		}
	}
}
