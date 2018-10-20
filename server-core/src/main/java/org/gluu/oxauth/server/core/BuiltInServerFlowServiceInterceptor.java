package org.gluu.oxauth.server.core;

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
@Priority(1)
public class BuiltInServerFlowServiceInterceptor {

    @AroundInvoke
    public Object manageTransaction(InvocationContext ctx) throws Exception {
        System.out.println("Built-in interceptor");
        return ctx.proceed();
    }
}
