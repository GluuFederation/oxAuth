package org.gluu.oxauth.server.core;

import org.gluu.oxauth.server.interfaces.Interceptable;
import org.gluu.oxauth.server.interfaces.InterceptorInterface;

import javax.enterprise.context.ApplicationScoped;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class ServerFlowService implements InterceptorInterface {

    @Interceptable
    public boolean handle(String a, Integer b) {
        System.out.println("Server - a: " + a + ", b: " + b);
        return false;
    }
}
