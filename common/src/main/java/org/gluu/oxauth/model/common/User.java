/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.gluu.persist.annotation.DataEntry;
import org.gluu.persist.annotation.ObjectClass;
import org.gluu.persist.model.base.CustomObjectAttribute;
import org.gluu.util.StringHelper;

/**
 * @author Yuriy Movchan Date: 06/11/2013
 */
@DataEntry
@ObjectClass(value = "gluuPerson")
public class User extends SimpleUser {

    private static final long serialVersionUID = 6634191420188575733L;

    @Deprecated
	public void setAttribute(String attributeName, String attributeValue) {
		setAttribute(attributeName, attributeValue, null);
	}

	public void setAttribute(String attributeName, String attributeValue, Boolean multiValued) {
		CustomObjectAttribute attribute = new CustomObjectAttribute(attributeName, attributeValue);
		if (multiValued != null) {
			attribute.setMultiValued(multiValued);
		}

		removeAttribute(attributeName);
		getCustomAttributes().add(attribute);
	}

    @Deprecated
	public void setAttribute(String attributeName, String[] attributeValues) {
    	setAttribute(attributeName, attributeValues, null);
	}

	public void setAttribute(String attributeName, String[] attributeValues, Boolean multiValued) {
		CustomObjectAttribute attribute = new CustomObjectAttribute(attributeName, Arrays.asList(attributeValues));
		if (multiValued != null) {
			attribute.setMultiValued(multiValued);
		}

		removeAttribute(attributeName);
		getCustomAttributes().add(attribute);
	}

    @Deprecated
	public void setAttribute(String attributeName, List<String> attributeValues) {
		setAttribute(attributeName, attributeValues, null);
	}

	public void setAttribute(String attributeName, List<String> attributeValues, Boolean multiValued) {
		CustomObjectAttribute attribute = new CustomObjectAttribute(attributeName, attributeValues);
		if (multiValued != null) {
			attribute.setMultiValued(multiValued);
		}

		removeAttribute(attributeName);
		getCustomAttributes().add(attribute);
	}
	
	public void removeAttribute(String attributeName) {
		for (Iterator<CustomObjectAttribute> it = getCustomAttributes().iterator(); it.hasNext();) {
			if (StringHelper.equalsIgnoreCase(attributeName, it.next().getName())) {
				it.remove();
				break;
			}
		}
	}

    public String getStatus() {
        return getAttribute("gluuStatus");
    }
}