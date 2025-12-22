package com.iotplatform.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TenantDTO {
    
    private String id;
    private String name;
    private String tenantId;
    private String description;
    private String contactEmail;
    private String contactPhone;
    private String company;
    private String address;
    private String city;
    private String state;
    private String postalCode;
    private String country;
    private Integer maxUsers;
    private Integer maxDevices;
    private String subscriptionPlan;
    private String subscriptionStatus;
    private LocalDateTime trialEndsAt;
    private boolean active;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Long userCount;
    private Long deviceCount;
}