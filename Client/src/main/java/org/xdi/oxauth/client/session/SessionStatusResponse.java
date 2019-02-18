package org.xdi.oxauth.client.session;

import java.io.Serializable;
import org.xdi.oxauth.client.BaseResponse;
import org.xdi.oxauth.model.session.SessionState;
import org.xdi.oxauth.model.session.SessionCustomState;

public class SessionStatusResponse extends BaseResponse implements Serializable {

    private SessionState state;
    private SessionCustomState customState;
    private Integer authTime;

    public SessionStatusResponse(int status) {
        
        super(status);
        this.state = null;
        this.customState = null;
        this.authTime = null;
    }

    public SessionState getState() {

        return this.state;
    }

    public SessionStatusResponse setState(SessionState state) {

        this.state = state;
        return this;
    }

    public SessionCustomState getCustomState() {

        return this.customState;
    }

    public SessionStatusResponse setCustomState(SessionCustomState customState) {

        this.customState = customState;
        return this;
    }

    public Integer getAuthTime() {

        return this.authTime;
    }

    public SessionStatusResponse setAuthTime(Integer authTime) {

        this.authTime = authTime;
        return this;
    }

    @Override
    public String toString() {

        return "SessionStatusResponse{" +
            "state='"+state+"'"+
            "custom_state='"+customState+"'"+
            "auth_time='"+authTime+"'"+
            "}";
    }
    
}