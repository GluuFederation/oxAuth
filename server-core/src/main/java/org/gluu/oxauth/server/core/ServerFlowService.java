package org.gluu.oxauth.server.core;

import org.gluu.oxauth.server.interfaces.Interceptable;

import javax.enterprise.context.ApplicationScoped;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class ServerFlowService {

    @Interceptable
    public void handle(String param) {
        System.out.println(param);
    }
}
