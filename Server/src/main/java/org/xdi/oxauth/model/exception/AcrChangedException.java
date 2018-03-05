package org.xdi.oxauth.model.exception;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 16/06/2015
 */

public class AcrChangedException extends Exception {

    private boolean methodEnabled = true;

    public AcrChangedException() {
    }

    public AcrChangedException(Throwable cause) {
        super(cause);
    }

    public AcrChangedException(String message) {
        super(message);
    }

    public AcrChangedException(String message, Throwable cause) {
        super(message, cause);
    }

    public boolean isMethodEnabled() {
        return methodEnabled;
    }

    public void setMethodEnabled(boolean methodEnabled) {
        this.methodEnabled = methodEnabled;
    }

}
