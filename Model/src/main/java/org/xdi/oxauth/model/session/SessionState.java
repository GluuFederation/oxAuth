package org.xdi.oxauth.model.session;

public enum SessionState {

    UNKNOWN("unknown"),
    UNAUTHENTICATED("unauthenticated"),
    AUTHENTICATED("authenticated");

    private String value;

    private SessionState(String value) {
        this.value = value;
    }

    public static final SessionState fromString(String value) {

        if(value!=null) {
            for(SessionState state: SessionState.values()) {
                if(value.equals(state.value)) {
                    return state;
                }
            }
        }
        return null;
    }
}