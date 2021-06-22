package org.gluu.oxauth.ping;

public class HttpException extends Exception {
    
    private Integer statusCode;
    
    public HttpException(String message) {
        super(message);
    }
    
    public HttpException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public HttpException(Integer statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
 
}
