package org.gluu.oxauth.model.util;

/**
 * @author Yuriy Z
 */
public class Tester {
    private Tester() {
    }

    public static void showTitle(String title) {
        title = "TEST: " + title;

        System.out.println("#######################################################");
        System.out.println(title);
        System.out.println("#######################################################");
    }
}
