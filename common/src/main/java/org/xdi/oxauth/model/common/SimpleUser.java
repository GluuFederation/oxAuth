/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.common;

import org.codehaus.jettison.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xdi.ldap.model.CustomAttribute;
import org.xdi.oxauth.model.exception.InvalidClaimException;
import org.xdi.util.StringHelper;

import java.util.List;

/**
 * @author Javier Rojas Blum Date: 11.25.2011
 */
public class SimpleUser extends org.xdi.ldap.model.SimpleUser {

    private final static Logger log = LoggerFactory.getLogger(SimpleUser.class);

    private static final long serialVersionUID = -2634191420188575733L;

    public Object getAttribute(String userAttribute, boolean optional) throws InvalidClaimException {
        Object attribute = null;

        for (org.xdi.ldap.model.CustomAttribute customAttribute : customAttributes) {
            if (customAttribute.getName().equals(userAttribute)) {
                List<String> values = customAttribute.getValues();
                if (values != null) {
                    if (values.size() == 1) {
                        attribute = values.get(0);
                    } else {
                        JSONArray array = new JSONArray();
                        for (String v : values) {
                            array.put(v);
                        }
                        attribute = array;
                    }
                }

                break;
            }
        }

        log.trace("User's attribute, name - {}, value - {}", userAttribute, attribute);

        if (attribute != null) {
            return attribute;
        } else if (optional) {
            return attribute;
        } else {
            throw new InvalidClaimException("The claim " + userAttribute + " was not found.");
        }
    }

    public List<String> getAttributeValues(String ldapAttribute) {
        List<String> attributes = null;
        if (ldapAttribute != null && !ldapAttribute.isEmpty()) {
            for (CustomAttribute customAttribute : customAttributes) {
                if (StringHelper.equalsIgnoreCase(ldapAttribute, customAttribute.getName())) {
                    attributes = customAttribute.getValues();
                    break;
                }
            }
        }

        return attributes;
    }

}