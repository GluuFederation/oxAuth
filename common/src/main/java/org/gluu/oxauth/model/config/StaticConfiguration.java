/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.config;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.apache.commons.lang3.builder.DiffBuilder;
import org.apache.commons.lang3.builder.DiffResult;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.gluu.oxauth.model.configuration.Configuration;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @version 0.9 February 12, 2015
 */
@XmlRootElement(name = "static")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonIgnoreProperties(ignoreUnknown = true)
public class StaticConfiguration implements Configuration {

    @XmlElement(name = "base-dn")
    private BaseDnConfiguration baseDn;

    public BaseDnConfiguration getBaseDn() {
        return baseDn;
    }

    public void setBaseDn(BaseDnConfiguration p_baseDn) {
        baseDn = p_baseDn;
    }

	@Override
	public DiffResult diff(Configuration newObj) {
		StaticConfiguration obj = (StaticConfiguration) newObj;
		 return new DiffBuilder(this, obj, ToStringStyle.SHORT_PREFIX_STYLE)
				 .append("baseDn", this.baseDn, obj.baseDn)
				 .build();
				 
	}
}
