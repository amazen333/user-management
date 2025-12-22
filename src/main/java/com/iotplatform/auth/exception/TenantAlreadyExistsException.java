package com.iotplatform.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class TenantAlreadyExistsException extends RuntimeException {
    
    public TenantAlreadyExistsException(String message) {
        super(message);
    }
}