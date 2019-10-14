package org.xdi.oxauth.service;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequestScoped
@Named
public class HttpServletContextService {

    @Inject
    private HttpServletRequest request;

    @Inject
    private HttpServletResponse response;

    public HttpServletRequest getRequest() {

        return this.request;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    public HttpServletResponse getResponse() {

        return this.response;
    }

    public void setResponse(HttpServletResponse response) {

        this.response = response;
    }
}