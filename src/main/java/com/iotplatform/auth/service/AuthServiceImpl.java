package com.iotplatform.auth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.iotplatform.auth.dto.ChangePasswordRequest;
import com.iotplatform.auth.dto.JwtResponse;
import com.iotplatform.auth.dto.LoginRequest;
import com.iotplatform.auth.dto.RefreshTokenRequest;
import com.iotplatform.auth.dto.RegisterRequest;
import com.iotplatform.auth.dto.ResetPasswordRequest;
import com.iotplatform.auth.dto.UpdateProfileRequest;
import com.iotplatform.auth.dto.UserDTO;
import com.iotplatform.auth.exception.AccountDisabledException;
import com.iotplatform.auth.exception.AccountLockedException;
import com.iotplatform.auth.exception.EmailAlreadyExistsException;
import com.iotplatform.auth.exception.EmailAlreadyVerifiedException;
import com.iotplatform.auth.exception.InvalidPasswordException;
import com.iotplatform.auth.exception.InvalidTokenException;
import com.iotplatform.auth.exception.PasswordMismatchException;
import com.iotplatform.auth.exception.RoleNotFoundException;
import com.iotplatform.auth.exception.TenantAlreadyExistsException;
import com.iotplatform.auth.exception.UnauthorizedException;
import com.iotplatform.auth.exception.UserMapper;
import com.iotplatform.auth.exception.UserNotFoundException;
import com.iotplatform.auth.exception.UsernameAlreadyExistsException;
import com.iotplatform.auth.model.RefreshToken;
import com.iotplatform.auth.model.Role;
import com.iotplatform.auth.model.Tenant;
import com.iotplatform.auth.model.User;
import com.iotplatform.auth.repo.RefreshTokenRepository;
import com.iotplatform.auth.repo.TenantRepository;
import com.iotplatform.auth.repo.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {
    
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TenantRepository tenantRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final EmailService emailService;
    
    @Override
    @Transactional
    public JwtResponse login(LoginRequest request) {
        try {
            User user = userRepository.findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
            
            // Check if user is enabled
            if (!user.isEnabled()) {
                throw new AccountDisabledException("Account is disabled");
            }
            
            // Check if account is locked
            if (user.isLocked()) {
                throw new AccountLockedException("Account is locked due to multiple failed login attempts");
            }
            
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    user.getUsername(), 
                    request.getPassword()
                )
            );
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Reset login attempts on successful login
            user.resetLoginAttempts();
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            
            // Generate tokens
            String jwtToken = jwtService.generateToken(
                (UserDetails) authentication.getPrincipal(),
                user.getId().toString(),
                user.getTenantId()
            );
            
            String refreshToken = jwtService.generateRefreshToken(
                (UserDetails) authentication.getPrincipal(),
                user.getId().toString()
            );
            
            // Save refresh token
            saveRefreshToken(user, refreshToken);
            
            // Get user roles
            List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());
            
            return JwtResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .userId(user.getId().toString())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .tenantId(user.getTenantId())
                .roles(roles)
                .expiresIn(jwtService.getExpirationTime())
                .build();
            
        } catch (BadCredentialsException e) {
            // Increment login attempts
            User user = userRepository.findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElse(null);
            
            if (user != null) {
                user.incrementLoginAttempts();
                userRepository.save(user);
                
                if (user.isLocked()) {
                    log.warn("User {} account locked after multiple failed attempts", user.getUsername());
                    emailService.sendAccountLockedEmail(user.getEmail(), user.getUsername());
                }
            }
            
            throw new BadCredentialsException("Invalid credentials");
        }
    }
    
    @Override
    @Transactional
    public UserDTO register(RegisterRequest request) {
        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UsernameAlreadyExistsException("Username is already taken");
        }
        
        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email is already in use");
        }
        
        // Check if tenant name exists
        if (tenantRepository.existsByName(request.getTenantName())) {
            throw new TenantAlreadyExistsException("Tenant name is already taken");
        }
        
        // Generate tenant ID
        String tenantId = generateTenantId(request.getTenantName());
        
        // Create tenant
        Tenant tenant = Tenant.builder()
            .name(request.getTenantName())
            .tenantId(tenantId)
            .contactEmail(request.getEmail())
            .contactPhone(request.getPhone())
            .company(request.getCompany())
            .trialEndsAt(LocalDateTime.now().plusDays(30))
            .active(true)
            .build();
        
        tenant = tenantRepository.save(tenant);
        
        // Create user
        User user = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .phone(request.getPhone())
            .company(request.getCompany())
            .tenantId(tenant.getTenantId())
            .passwordChangedAt(LocalDateTime.now())
            .emailVerified(false)
            .emailVerificationToken(generateVerificationToken())
            .build();
        
        // Assign default role
        Role userRole = roleRepository.findByName(Role.RoleName.ROLE_USER)
            .orElseThrow(() -> new RoleNotFoundException("User role not found"));
        user.getRoles().add(userRole);
        
        // Assign admin role for first user in tenant
        Role adminRole = roleRepository.findByName(Role.RoleName.ROLE_ADMIN)
            .orElseThrow(() -> new RoleNotFoundException("Admin role not found"));
        user.getRoles().add(adminRole);
        
        user = userRepository.save(user);
        
        // Send verification email
        emailService.sendVerificationEmail(user.getEmail(), user.getUsername(), 
                                          user.getEmailVerificationToken());
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional
    public JwtResponse refreshToken(RefreshTokenRequest request) {
        try {
            String refreshToken = request.getRefreshToken();
            
            // Validate refresh token
            if (!jwtService.isRefreshToken(refreshToken)) {
                throw new InvalidTokenException("Invalid refresh token");
            }
            
            String username = jwtService.extractUsername(refreshToken);
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
            
            // Check if refresh token exists and is valid
            RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));
            
            if (!storedToken.isValid()) {
                throw new InvalidTokenException("Refresh token is invalid or expired");
            }
            
            // Generate new tokens
            UserDetails userDetails = loadUserByUsername(user.getUsername());
            
            String newJwtToken = jwtService.generateToken(
                userDetails,
                user.getId().toString(),
                user.getTenantId()
            );
            
            String newRefreshToken = jwtService.generateRefreshToken(
                userDetails,
                user.getId().toString()
            );
            
            // Revoke old refresh token
            storedToken.setRevoked(true);
            refreshTokenRepository.save(storedToken);
            
            // Save new refresh token
            saveRefreshToken(user, newRefreshToken);
            
            // Get user roles
            List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());
            
            return JwtResponse.builder()
                .token(newJwtToken)
                .refreshToken(newRefreshToken)
                .userId(user.getId().toString())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .tenantId(user.getTenantId())
                .roles(roles)
                .expiresIn(jwtService.getExpirationTime())
                .build();
            
        } catch (Exception e) {
            throw new InvalidTokenException("Failed to refresh token: " + e.getMessage());
        }
    }
    
    @Override
    @Transactional
    public void logout(String token) {
        try {
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            
            String username = jwtService.extractUsername(token);
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
            
            // Revoke all refresh tokens for this user
            refreshTokenRepository.revokeAllByUser(user);
            
            SecurityContextHolder.clearContext();
            
        } catch (Exception e) {
            log.warn("Error during logout: {}", e.getMessage());
        }
    }
    
    @Override
    @Transactional(readOnly = true)
    public UserDTO getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UnauthorizedException("User not authenticated");
        }
        
        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional
    public UserDTO updateProfile(UpdateProfileRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // Update fields if provided
        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            // Check if new email is already in use
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new EmailAlreadyExistsException("Email is already in use");
            }
            
            user.setEmail(request.getEmail());
            user.setEmailVerified(false);
            user.setEmailVerificationToken(generateVerificationToken());
            
            // Send verification email for new email
            emailService.sendVerificationEmail(user.getEmail(), user.getUsername(), 
                                              user.getEmailVerificationToken());
        }
        
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        
        if (request.getCompany() != null) {
            user.setCompany(request.getCompany());
        }
        
        user = userRepository.save(user);
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional
    public void changePassword(ChangePasswordRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new InvalidPasswordException("Current password is incorrect");
        }
        
        // Verify new password matches confirmation
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException("New passwords do not match");
        }
        
        // Check if new password is same as old password
        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new InvalidPasswordException("New password must be different from current password");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);
        
        // Revoke all refresh tokens (force logout from all devices)
        refreshTokenRepository.revokeAllByUser(user);
        
        // Send password change notification
        emailService.sendPasswordChangedEmail(user.getEmail(), user.getUsername());
    }
    
    @Override
    @Transactional
    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("User with this email not found"));
        
        // Generate reset token
        String resetToken = generateResetToken();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetExpires(LocalDateTime.now().plusHours(24));
        userRepository.save(user);
        
        // Send password reset email
        emailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), resetToken);
    }
    
    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByPasswordResetToken(request.getToken())
            .orElseThrow(() -> new InvalidTokenException("Invalid or expired reset token"));
        
        // Check if token is expired
        if (user.getPasswordResetExpires().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Reset token has expired");
        }
        
        // Verify passwords match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException("Passwords do not match");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setPasswordResetToken(null);
        user.setPasswordResetExpires(null);
        userRepository.save(user);
        
        // Revoke all refresh tokens
        refreshTokenRepository.revokeAllByUser(user);
        
        // Send password reset confirmation
        emailService.sendPasswordResetConfirmationEmail(user.getEmail(), user.getUsername());
    }
    
    @Override
    @Transactional
    public void verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
            .orElseThrow(() -> new InvalidTokenException("Invalid verification token"));
        
        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        userRepository.save(user);
        
        log.info("Email verified for user: {}", user.getUsername());
    }
    
    @Override
    @Transactional
    public void resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UserNotFoundException("User with this email not found"));
        
        if (user.isEmailVerified()) {
            throw new EmailAlreadyVerifiedException("Email is already verified");
        }
        
        // Generate new verification token
        user.setEmailVerificationToken(generateVerificationToken());
        userRepository.save(user);
        
        // Send verification email
        emailService.sendVerificationEmail(user.getEmail(), user.getUsername(), 
                                          user.getEmailVerificationToken());
    }
    
    // Helper methods
    private UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
        
        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(user.getRoles().stream()
                .map(role -> new org.springframework.security.core.authority.SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList()))
            .accountExpired(!user.isAccountNonExpired())
            .accountLocked(!user.isAccountNonLocked())
            .credentialsExpired(!user.isCredentialsNonExpired())
            .disabled(!user.isEnabled())
            .build();
    }
    
    private void saveRefreshToken(User user, String refreshToken) {
        RefreshToken token = RefreshToken.builder()
            .user(user)
            .token(refreshToken)
            .expiryDate(LocalDateTime.now().plusDays(7))
            .ipAddress(getClientIp())
            .userAgent(getUserAgent())
            .build();
        
        refreshTokenRepository.save(token);
    }
    
    private String generateTenantId(String tenantName) {
        // Convert tenant name to URL-friendly format
        String baseId = tenantName.toLowerCase()
            .replaceAll("[^a-z0-9]", "-")
            .replaceAll("-+", "-")
            .replaceAll("^-|-$", "");
        
        // Ensure uniqueness
        String tenantId = baseId;
        int counter = 1;
        
        while (tenantRepository.existsByTenantId(tenantId)) {
            tenantId = baseId + "-" + counter;
            counter++;
        }
        
        return tenantId;
    }
    
    private String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }
    
    private String generateResetToken() {
        return UUID.randomUUID().toString();
    }
    
    private String getClientIp() {
        // Implement based on your framework (Spring Security, etc.)
        return "127.0.0.1";
    }
    
    private String getUserAgent() {
        // Implement based on your framework
        return "Unknown";
    }
}