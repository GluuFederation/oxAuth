package org.xdi.oxauth.service;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

@RequestScoped
@Named
public class RequestObjectsService {

    @Inject
    private HttpServletRequest httpRequest;


    public HttpServletRequest getHttpRequest() {

        return this.httpRequest;
    }

    public void setHttpRequest(HttpServletRequest httpRequest) {
        this.httpRequest = httpRequest;
    }
}