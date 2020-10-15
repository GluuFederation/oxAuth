/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.model.common;

import java.util.List;

import org.json.JSONArray;
import org.gluu.oxauth.model.exception.InvalidClaimException;
import org.gluu.persist.model.base.CustomAttribute;
import org.gluu.persist.model.base.CustomObjectAttribute;
import org.gluu.util.StringHelper;

/**
 * @author Javier Rojas Blum
 * @version May 3, 2019
 */
public class SimpleUser extends org.gluu.persist.model.base.SimpleUser {

    private static final long serialVersionUID = -2634191420188575733L;

    public Object getAttribute(String attributeName, boolean optional, boolean multivalued) throws InvalidClaimException {
        Object attribute = null;

        List<String> values = getAttributeValues(attributeName);
        if (values != null) {
            if (multivalued) {
                JSONArray array = new JSONArray();
                for (String v : values) {
                    array.put(v);
                }
                attribute = array;
            } else {
                attribute = values.get(0);
            }
        }

        if (attribute != null) {
            return attribute;
        } else if (optional) {
            return attribute;
        } else {
            throw new InvalidClaimException("The claim " + attributeName + " was not found.");
        }
    }

}