package org.gluu.oxauth.server.core;

import org.jboss.weld.environment.se.events.ContainerInitialized;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

/**
 * @author Yuriy Zabrovarnyy
 */
@ApplicationScoped
public class Server {

    @Inject
    private ServerFlowService serverFlowService;

    public void start(@Observes ContainerInitialized event) {
        int n = 0;
        while (n < 1000) {
            serverFlowService.handle("server");

            try {
                Thread.sleep(4000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            n++;
        }
    }
}
