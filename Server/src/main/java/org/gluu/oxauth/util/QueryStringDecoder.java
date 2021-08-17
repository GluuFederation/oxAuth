/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.oxauth.util;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides functionality to parse query strings.
 *
 * @author Javier Rojas Blum
 * @version November 24, 2017
 */
public class QueryStringDecoder {

    /**
     * Decodes a query string and returns a map with the parsed query string
     * parameters as keys and its values. The parameter values are not 
     * urldecoded
     *
     * @param queryString The query string.
     * @return A map with the parsed query string parameters and its values.
     */
    public static Map<String,String> decode(String queryString) {

        return decode(queryString,false);
    }

    /**
     * Decodes a query string and returns a map with the parsed query string
     * parameters as keys and its values.
     *
     * @param queryString The query string.
     * @param urlDecode   Boolean indicating if the parameter values should be urldecoded
     * @return A map with the parsed query string parameters and its values.
     */
    public static Map<String, String> decode(String queryString, boolean urlDecode) {
        Map<String, String> map = new HashMap<String, String>();

        if (queryString != null) {
            String[] params = queryString.split("&");
            for (String param : params) {
                String[] nameValue = param.split("=");
                String name = nameValue.length > 0 ? nameValue[0] : "";
                String value = nameValue.length > 1 ? nameValue[1] : "";
                if(urlDecode) {
                    try {
                        map.put(name, URLDecoder.decode(value,"UTF-8"));
                    }catch(UnsupportedEncodingException e) {
                        map.put(name,value);
                    }
                }else {
                    map.put(name,value);
                }
            }
        }

        return map;
    }
}