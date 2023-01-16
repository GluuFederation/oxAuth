/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.apache.commons.lang3.builder.DiffBuilder;
import org.apache.commons.lang3.builder.DiffResult;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.gluu.oxauth.model.configuration.Configuration;
import org.gluu.oxauth.model.jwk.JSONWebKeySet;

import javax.enterprise.inject.Vetoed;

/**
 * @author Yuriy Movchan
 * @version 03/15/2017
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Vetoed
public class WebKeysConfiguration extends JSONWebKeySet implements Configuration {
	
	@Override
	public DiffResult diff(Configuration newObj) {
		WebKeysConfiguration obj = (WebKeysConfiguration) newObj;
		 return null;
				 
	}

}
