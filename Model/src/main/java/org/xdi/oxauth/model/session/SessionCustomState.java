package org.xdi.oxauth.model.session;

public enum SessionCustomState {

    APPROVED("approved"),
    EXPIRED("expired"),
    DECLINED("declined"),
    UNKNOWN("unknown");

    private String value;

    private SessionCustomState(String value) {
        this.value = value;
    }

    public static final SessionCustomState fromString(String value) {

        if(value == null) {
            for(SessionCustomState state: SessionCustomState.values()) {
                if(value.equals(state.value)) {
                    return state;
                }
            }
        }
        return null;
    }
}