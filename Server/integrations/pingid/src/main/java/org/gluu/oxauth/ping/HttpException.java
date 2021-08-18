package org.gluu.oxauth.ping;

public class HttpException extends Exception {
    
    private Integer statusCode;
    private String response;
    
    public HttpException(String message) {
        super(message);
    }
    
    public HttpException(String message, Throwable cause, String response) {
        super(message, cause);
        this.response = response;
    }
    
    public HttpException(Integer statusCode, String message, String response) {
        super(message);
        this.statusCode = statusCode;
        this.response = response;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public String getResponse() {
        return response;
    }
 
}
