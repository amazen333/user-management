package com.iotplatform.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import lombok.extern.slf4j.Slf4j;


@Service
@Slf4j
public class EmailService {
    
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    
    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;
    
    @Value("${spring.mail.username}")
    private String fromEmail;
    
    public EmailService(JavaMailSender mailSender, TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }
    
    @Async
    public void sendVerificationEmail(String to, String username, String token) {
        try {
            String verificationUrl = baseUrl + "/auth/verify-email?token=" + token;
            
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("verificationUrl", verificationUrl);
            context.setVariable("supportEmail", "support@iotplatform.com");
            
            String htmlContent = templateEngine.process("email/verification", context);
            
            sendEmail(to, "Verify Your Email - IoT Platform", htmlContent);
            log.info("Verification email sent to: {}", to);
            
        } catch (Exception e) {
            log.error("Failed to send verification email to {}: {}", to, e.getMessage());
        }
    }
    
    @Async
    public void sendPasswordResetEmail(String to, String username, String token) {
        try {
            String resetUrl = baseUrl + "/auth/reset-password?token=" + token;
            
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("resetUrl", resetUrl);
            context.setVariable("expiryHours", 24);
            
            String htmlContent = templateEngine.process("email/password-reset", context);
            
            sendEmail(to, "Reset Your Password - IoT Platform", htmlContent);
            log.info("Password reset email sent to: {}", to);
            
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}: {}", to, e.getMessage());
        }
    }
    
    @Async
    public void sendPasswordChangedEmail(String to, String username) {
        try {
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("supportEmail", "support@iotplatform.com");
            
            String htmlContent = templateEngine.process("email/password-changed", context);
            
            sendEmail(to, "Password Changed - IoT Platform", htmlContent);
            log.info("Password changed notification sent to: {}", to);
            
        } catch (Exception e) {
            log.error("Failed to send password changed email to {}: {}", to, e.getMessage());
        }
    }
    
    @Async
    public void sendPasswordResetConfirmationEmail(String to, String username) {
        try {
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("supportEmail", "support@iotplatform.com");
            
            String htmlContent = templateEngine.process("email/password-reset-confirmation", context);
            
            sendEmail(to, "Password Reset Confirmation - IoT Platform", htmlContent);
            log.info("Password reset confirmation sent to: {}", to);
            
        } catch (Exception e) {
            log.error("Failed to send password reset confirmation to {}: {}", to, e.getMessage());
        }
    }
    
    @Async
    public void sendAccountLockedEmail(String to, String username) {
        try {
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("supportEmail", "support@iotplatform.com");
            context.setVariable("unlockUrl", baseUrl + "/auth/unlock-account");
            
            String htmlContent = templateEngine.process("email/account-locked", context);
            
            sendEmail(to, "Account Locked - IoT Platform", htmlContent);
            log.info("Account locked notification sent to: {}", to);
            
        } catch (Exception e) {
            log.error("Failed to send account locked email to {}: {}", to, e.getMessage());
        }
    }
    
    @Async
    public void sendWelcomeEmail(String to, String username, String tenantName) {
        try {
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("tenantName", tenantName);
            context.setVariable("dashboardUrl", baseUrl + "/dashboard");
            context.setVariable("supportEmail", "support@iotplatform.com");
            
            String htmlContent = templateEngine.process("email/welcome", context);
            
            sendEmail(to, "Welcome to IoT Platform", htmlContent);
            log.info("Welcome email sent to: {}", to);
            
        } catch (Exception e) {
            log.error("Failed to send welcome email to {}: {}", to, e.getMessage());
        }
    }
    
    private void sendEmail(String to, String subject, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setFrom(fromEmail);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        
        mailSender.send(message);
    }

    @Async
    public void sendAdminPasswordResetEmail(String to, String username, String tempPassword) {
        try {
            Context context = new Context();
            context.setVariable("username", username);
            context.setVariable("tempPassword", tempPassword);
            context.setVariable("loginUrl", baseUrl + "/login");
            context.setVariable("supportEmail", "support@iotplatform.com");

            String htmlContent = templateEngine.process("email/admin-password-reset", context);

            sendEmail(to, "Temporary Password - IoT Platform", htmlContent);
            log.info("Admin password reset email sent to: {}", to);

        } catch (Exception e) {
            log.error("Failed to send admin password reset email to {}: {}", to, e.getMessage());
        }
    }
}