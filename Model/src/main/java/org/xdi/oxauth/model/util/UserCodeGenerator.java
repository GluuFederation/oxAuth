/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.util;

import org.apache.commons.lang.RandomStringUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * Generator the end-user verification code. Used in the Device Authorization Flow.
 *
 * @author Javier Rojas Blum
 * @version January 23, 2017
 */
public class UserCodeGenerator {

    public static String generateUserCode() {
        //return RandomStringUtils.randomAlphanumeric(8);
        return RandomStringUtils.randomAlphabetic(8);
    }

    public static void main(String[] args) {
        //int n = 1000000;
        int n = 100;
        Set<String> set = new HashSet<String>();
        for (int i = 0; i < n; i++) {
            String userCode = generateUserCode();

            set.add(userCode);
            System.out.println(userCode);
        }
        System.out.println("Duplicated: " + (n - set.size()));
    }
}
