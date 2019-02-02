/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.util;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Javier Rojas Blum
 * @version February 1, 2019
 */
public class StoragerelaySchemeUri {

    public static final String STORAGE_RELAY_SCHEME = "storagerelay";

    private String scheme;
    private String host;
    private String id;

    public StoragerelaySchemeUri(String uriString) throws URISyntaxException, UnsupportedEncodingException {
        URI uri = new URI(uriString);

        scheme = uri.getAuthority();

        String path = uri.getPath();
        if (path != null && path.startsWith("/")) {
            host = path.substring(1);
        }

        String query = uri.getQuery();
        if (query != null) {
            Map<String, List<String>> queryMap = splitQuery(query);
            if (queryMap.containsKey("id")) {
                id = queryMap.get("id").get(0);
            }
        }
    }

    public String getScheme() {
        return scheme;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return STORAGE_RELAY_SCHEME + "://" + scheme + "/" + host + "?id=" + id;
    }

    private static Map<String, List<String>> splitQuery(String queryString) throws UnsupportedEncodingException {
        final Map<String, List<String>> query_pairs = new LinkedHashMap<String, List<String>>();
        final String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            final int idx = pair.indexOf("=");
            final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
            if (!query_pairs.containsKey(key)) {
                query_pairs.put(key, new LinkedList<String>());
            }
            final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
            query_pairs.get(key).add(value);
        }
        return query_pairs;
    }
}