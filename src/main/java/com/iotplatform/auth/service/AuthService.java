package com.iotplatform.auth.service;

import com.iotplatform.auth.dto.*;

public interface AuthService {
    
    JwtResponse login(LoginRequest request);
    
    UserDTO register(RegisterRequest request);
    
    JwtResponse refreshToken(RefreshTokenRequest request);
    
    void logout(String token);
    
    UserDTO getCurrentUser();
    
    UserDTO updateProfile(UpdateProfileRequest request);
    
    void changePassword(ChangePasswordRequest request);
    
    void forgotPassword(String email);
    
    void resetPassword(ResetPasswordRequest request);
    
    void verifyEmail(String token);
    
    void resendVerificationEmail(String email);
}