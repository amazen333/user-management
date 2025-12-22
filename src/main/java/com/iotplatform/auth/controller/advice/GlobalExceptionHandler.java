package com.iotplatform.auth.controller.advice;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.iotplatform.auth.exception.AccountDisabledException;
import com.iotplatform.auth.exception.AccountLockedException;
import com.iotplatform.auth.exception.EmailAlreadyExistsException;
import com.iotplatform.auth.exception.EmailAlreadyVerifiedException;
import com.iotplatform.auth.exception.InvalidPasswordException;
import com.iotplatform.auth.exception.InvalidTokenException;
import com.iotplatform.auth.exception.PasswordMismatchException;
import com.iotplatform.auth.exception.RateLimitExceededException;
import com.iotplatform.auth.exception.RoleNotFoundException;
import com.iotplatform.auth.exception.TenantAlreadyExistsException;
import com.iotplatform.auth.exception.TenantLimitExceededException;
import com.iotplatform.auth.exception.TenantNotFoundException;
import com.iotplatform.auth.exception.TokenExpiredException;
import com.iotplatform.auth.exception.UnauthorizedException;
import com.iotplatform.auth.exception.UserNotFoundException;
import com.iotplatform.auth.exception.UsernameAlreadyExistsException;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    private final Map<String, Bucket> rateLimitBuckets = new HashMap<>();
    
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(
            BadCredentialsException ex, 
            HttpServletRequest request) {
        
        String clientIp = getClientIp(request);
        if (!tryConsumeRateLimitToken(clientIp)) {
            return buildRateLimitResponse();
        }
        
        log.warn("Bad credentials attempt from IP: {} - {}", clientIp, ex.getMessage());
        return buildErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "Invalid username or password",
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(AccountDisabledException.class)
    public ResponseEntity<ErrorResponse> handleAccountDisabledException(
            AccountDisabledException ex, 
            HttpServletRequest request) {
        
        log.warn("Account disabled attempt: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.FORBIDDEN,
            "ACCOUNT_DISABLED",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ErrorResponse> handleAccountLockedException(
            AccountLockedException ex, 
            HttpServletRequest request) {
        
        log.warn("Account locked attempt: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.FORBIDDEN,
            "ACCOUNT_LOCKED",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(CredentialsExpiredException.class)
    public ResponseEntity<ErrorResponse> handleCredentialsExpiredException(
            CredentialsExpiredException ex, 
            HttpServletRequest request) {
        
        log.warn("Credentials expired: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.FORBIDDEN,
            "CREDENTIALS_EXPIRED",
            "Your password has expired. Please reset your password.",
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUsernameAlreadyExistsException(
            UsernameAlreadyExistsException ex, 
            HttpServletRequest request) {
        
        log.warn("Username already exists: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.CONFLICT,
            "USERNAME_EXISTS",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyExistsException(
            EmailAlreadyExistsException ex, 
            HttpServletRequest request) {
        
        log.warn("Email already exists: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.CONFLICT,
            "EMAIL_EXISTS",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyVerifiedException(
            EmailAlreadyVerifiedException ex, 
            HttpServletRequest request) {
        
        log.warn("Email already verified: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "EMAIL_ALREADY_VERIFIED",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<ErrorResponse> handleInvalidPasswordException(
            InvalidPasswordException ex, 
            HttpServletRequest request) {
        
        log.warn("Invalid password: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "INVALID_PASSWORD",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(PasswordMismatchException.class)
    public ResponseEntity<ErrorResponse> handlePasswordMismatchException(
            PasswordMismatchException ex, 
            HttpServletRequest request) {
        
        log.warn("Password mismatch: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "PASSWORD_MISMATCH",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidTokenException(
            InvalidTokenException ex, 
            HttpServletRequest request) {
        
        log.warn("Invalid token: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "INVALID_TOKEN",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ErrorResponse> handleTokenExpiredException(
            TokenExpiredException ex, 
            HttpServletRequest request) {
        
        log.warn("Token expired: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "TOKEN_EXPIRED",
            "Your session has expired. Please login again.",
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(
            UserNotFoundException ex, 
            HttpServletRequest request) {
        
        log.warn("User not found: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.NOT_FOUND,
            "USER_NOT_FOUND",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleRoleNotFoundException(
            RoleNotFoundException ex, 
            HttpServletRequest request) {
        
        log.warn("Role not found: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.NOT_FOUND,
            "ROLE_NOT_FOUND",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(TenantNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleTenantNotFoundException(
            TenantNotFoundException ex, 
            HttpServletRequest request) {
        
        log.warn("Tenant not found: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.NOT_FOUND,
            "TENANT_NOT_FOUND",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(TenantAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleTenantAlreadyExistsException(
            TenantAlreadyExistsException ex, 
            HttpServletRequest request) {
        
        log.warn("Tenant already exists: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.CONFLICT,
            "TENANT_EXISTS",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(TenantLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleTenantLimitExceededException(
            TenantLimitExceededException ex, 
            HttpServletRequest request) {
        
        log.warn("Tenant limit exceeded: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "TENANT_LIMIT_EXCEEDED",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorizedException(
            UnauthorizedException ex, 
            HttpServletRequest request) {
        
        log.warn("Unauthorized: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "UNAUTHORIZED",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(
            AccessDeniedException ex, 
            HttpServletRequest request) {
        
        log.warn("Access denied: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.FORBIDDEN,
            "ACCESS_DENIED",
            "You don't have permission to access this resource",
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleRateLimitExceededException(
            RateLimitExceededException ex, 
            HttpServletRequest request) {
        
        log.warn("Rate limit exceeded: {}", ex.getMessage());
        return buildErrorResponse(
            HttpStatus.TOO_MANY_REQUESTS,
            "RATE_LIMIT_EXCEEDED",
            ex.getMessage(),
            request.getRequestURI()
        );
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex, 
            HttpServletRequest request) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        log.warn("Validation failed: {}", errors);
        
        ErrorResponse errorResponse = ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error("VALIDATION_FAILED")
            .message("Validation failed")
            .path(request.getRequestURI())
            .details(errors)
            .build();
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex, 
            HttpServletRequest request) {
        
        log.error("Unexpected error at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        
        // Don't expose internal error details in production
        String message = "An unexpected error occurred";
        if (isDevelopmentEnvironment()) {
            message = ex.getMessage();
        }
        
        return buildErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            message,
            request.getRequestURI()
        );
    }
    
    private ResponseEntity<ErrorResponse> buildErrorResponse(
            HttpStatus status, 
            String error, 
            String message,
            String path) {
        
        ErrorResponse errorResponse = ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(status.value())
            .error(error)
            .message(message)
            .path(path)
            .build();
        
        return ResponseEntity.status(status).body(errorResponse);
    }
    
    private ResponseEntity<ErrorResponse> buildRateLimitResponse() {
        ErrorResponse errorResponse = ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.TOO_MANY_REQUESTS.value())
            .error("RATE_LIMIT_EXCEEDED")
            .message("Too many login attempts. Please try again later.")
            .build();
        
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
    }
    
    private boolean tryConsumeRateLimitToken(String clientIp) {
        Bucket bucket = rateLimitBuckets.computeIfAbsent(clientIp, 
            k -> Bucket.builder()
                .addLimit(limit -> limit.capacity(5).refillGreedy(5, Duration.ofMinutes(1)))
                .build());
        
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        return probe.isConsumed();
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }
    
    private boolean isDevelopmentEnvironment() {
        String profile = System.getProperty("spring.profiles.active", "development");
        return "development".equals(profile) || "local".equals(profile);
    }
}