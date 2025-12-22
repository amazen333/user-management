package com.iotplatform.auth.model;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "tenants")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Tenant {
    
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.")
    private UUID id;
    
    @Column(nullable = false, unique = true)
    private String name;
    
    @Column(name = "tenant_id", nullable = false, unique = true)
    private String tenantId; // Used for API and database separation
    
    @Column(length = 500)
    private String description;
    
    @Column(name = "contact_email")
    private String contactEmail;
    
    @Column(name = "contact_phone")
    private String contactPhone;
    
    @Column
    private String address;
    
    @Column
    private String city;
    
    @Column
    private String state;
    
    @Column(name = "postal_code")
    private String postalCode;
    
    @Column
    private String country;
    
    @Column(name = "max_users")
    private Integer maxUsers = 10;
    
    @Column(name = "max_devices")
    private Integer maxDevices = 100;
    
    @Column(name = "subscription_plan")
    private String subscriptionPlan;
    
    @Column(name = "subscription_status")
    @Enumerated(EnumType.STRING)
    private SubscriptionStatus subscriptionStatus = SubscriptionStatus.TRIAL;
    
    @Column(name = "trial_ends_at")
    private LocalDateTime trialEndsAt;
    
    @Column(nullable = false)
    private boolean active = true;
    
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    public enum SubscriptionStatus {
        TRIAL,
        ACTIVE,
        SUSPENDED,
        CANCELLED,
        EXPIRED
    }

	public String getCompany() {
		// TODO Auto-generated method stub
		return null;
	}
}