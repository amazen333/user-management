package com.iotplatform.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {
    
    private String token;
    private String refreshToken;
    private String type = "Bearer";
    private String userId;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String tenantId;
    private List<String> roles;
    private Long expiresIn;
    
    public JwtResponse(String token, String refreshToken, String userId, String username, 
                      String email, String firstName, String lastName, String tenantId, 
                      List<String> roles, Long expiresIn) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.tenantId = tenantId;
        this.roles = roles;
        this.expiresIn = expiresIn;
    }
}