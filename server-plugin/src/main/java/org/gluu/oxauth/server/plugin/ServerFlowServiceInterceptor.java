package org.gluu.oxauth.server.plugin;

import org.gluu.oxauth.server.interfaces.Interceptable;

import javax.annotation.Priority;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

/**
 * @author Yuriy Zabrovarnyy
 */
@Interceptor
@Interceptable
@Priority(2)
public class ServerFlowServiceInterceptor {

    @AroundInvoke
    public Object manageTransaction(InvocationContext ctx) throws Exception {
        System.out.println("Interceptor from server-plugin.");
        return ctx.proceed();
    }
}
