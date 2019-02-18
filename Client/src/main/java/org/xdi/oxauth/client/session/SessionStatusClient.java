package org.xdi.oxauth.client.session;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;
import java.io.IOException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.xdi.oxauth.client.BaseClient;
import org.xdi.oxauth.model.session.SessionState;
import org.xdi.oxauth.model.session.SessionCustomState;
import static org.xdi.oxauth.model.session.SessionStatusResponseParam.*;

public class SessionStatusClient extends BaseClient<SessionStatusRequest,SessionStatusResponse> {

    private static final Logger log = Logger.getLogger(SessionStatusClient.class);

    private static final String mediaTypes = String.join(",",MediaType.TEXT_PLAIN, MediaType.APPLICATION_JSON);

    public SessionStatusClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {

        return HttpMethod.GET;
    }

    public SessionStatusResponse execGetStatus() {
        initClientRequest();

        return execGetStatusImpl();
    }

    private final SessionStatusResponse execGetStatusImpl() {
        setRequest(new SessionStatusRequest());

        clientRequest.accept(mediaTypes);
        clientRequest.setHttpMethod(getHttpMethod());

        try {
            clientResponse = clientRequest.get(String.class);
            int status = clientResponse.getStatus();
            setResponse(new SessionStatusResponse(status));
            String entity = clientResponse.getEntity(String.class);
            getResponse().setEntity(entity);
            getResponse().setHeaders(clientResponse.getMetadata());
            if(StringUtils.isNotBlank(entity)) {
                JSONObject jsonObj = new JSONObject(entity);

                if(jsonObj.has(STATE)) {
                    getResponse().setState(SessionState.fromString(jsonObj.getString(STATE)));
                }

                if(jsonObj.has(CUSTOM_STATE)) {
                    getResponse().setCustomState(SessionCustomState.fromString(jsonObj.getString(CUSTOM_STATE)));
                }

                if(jsonObj.has(AUTH_TIME) && !jsonObj.isNull(AUTH_TIME)) {
                    getResponse().setAuthTime(jsonObj.getInt(AUTH_TIME));
                }
            }
        }catch(JSONException e) {
            log.error("There is an error in the JSON response. Check the response for syntax errors or a wrong key",e);
        }catch(IOException e) {
            log.error(e.getMessage(),e);
        }catch(Exception e) {
            log.error(e.getMessage(),e);
        }finally {
            closeConnection();
        }

        return getResponse();
    }
}
