package org.gluu.oxauth.service;

import org.gluu.oxauth.model.ciba.CibaRequestSession;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@Named
@ApplicationScoped
public class CibaSessions implements Serializable {

    private Map<String, CibaRequestSession> sessions;

    public CibaSessions() {
        sessions = new HashMap<>();
    }

    public Map<String, CibaRequestSession> getSessions() {
        return sessions;
    }

    public void setSessions(Map<String, CibaRequestSession> sessions) {
        this.sessions = sessions;
    }

}
