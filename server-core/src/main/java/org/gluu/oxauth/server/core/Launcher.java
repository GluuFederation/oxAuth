package org.gluu.oxauth.server.core;

import org.jboss.weld.environment.se.Weld;

/**
 * @author Yuriy Zabrovarnyy
 */
public class Launcher {

    public static void main(String[] args) {
        Weld weld = new Weld().scanClasspathEntries();
        weld.initialize(); // shutdown hook is registered automatically for WeldContainer
    }
}
