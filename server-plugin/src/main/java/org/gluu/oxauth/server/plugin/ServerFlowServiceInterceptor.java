package org.gluu.oxauth.server.plugin;

import org.gluu.oxauth.server.interfaces.Interceptable;
import org.gluu.oxauth.server.interfaces.InterceptorInterface;

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
public class ServerFlowServiceInterceptor implements InterceptorInterface {

    @AroundInvoke
    public Object handle(InvocationContext ctx) throws Exception {
        System.out.println("Interceptor from server-plugin.");
        String a = (String) ctx.getParameters()[0];
        Integer b = (Integer) ctx.getParameters()[1];

        final boolean result = handle(a, b);
        ctx.proceed();
        return result;
    }

    @Override
    public boolean handle(String a, Integer b) {
        System.out.println("Plugin - a: " + a + ", b: " + b);
        return true;
    }
}
