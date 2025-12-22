package com.iotplatform.auth.exception;

import org.springframework.security.core.AuthenticationException;

public class AccountLockedException extends AuthenticationException {
    
    public AccountLockedException(String message) {
        super(message);
    }
    
    public AccountLockedException(String message, Throwable cause) {
        super(message, cause);
    }
}