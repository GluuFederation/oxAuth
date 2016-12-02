package org.xdi.oxauth.model.audit;

public enum Action {
    CLIENT_REGISTRATION("CLIENT_REGISTRATION"),
    CLIENT_UPDATE("CLIENT_UPDATE"),
    CLIENT_READ("CLIENT_READ"),
    CLIENT_DELETE("CLIENT_DELETE"),
    USER_AUTHORIZATION("USER_AUTHORIZATION"),
    USER_INFO("USER_INFO"),
    TOKEN_REQUEST("TOKEN_REQUEST"),
    TOKEN_VALIDATE("TOKEN_VALIDATE"),
    SESSION_UNAUTHENTICATED("SESSION_UNAUTHENTICATED"),
    SESSION_AUTHENTICATED("SESSION_AUTHENTICATED"),
    SESSION_DESTROYED("SESSION_DESTROYED");

    private String value;

    Action(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
