/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.service.net;

import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.slf4j.Logger;

/**
 * Provides operations with http/https requests
 *
 * @author Yuriy Movchan Date: 04/10/2023
 */
@ApplicationScoped
public class HttpService2 extends org.gluu.net.HttpServiceUtility implements Serializable {

	@Inject
	private Logger log;

	@PostConstruct
	public void init() {
		super.init();
	}

	@PreDestroy
	public void destroy() {
		super.destroy();
	}

	@Override
	public Logger getLogger() {
		return log;
	}

}
