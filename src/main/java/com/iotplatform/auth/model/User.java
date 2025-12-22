package com.iotplatform.auth.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users", uniqueConstraints = { @UniqueConstraint(columnNames = "username"),
		@UniqueConstraint(columnNames = "email") })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

	@Id
	@GeneratedValue(generator = "UUID",strategy = GenerationType.UUID)
	private UUID id;

	@NotBlank
	@Size(max = 50)
	@Column(nullable = false, unique = true)
	private String username;

	@NotBlank
	@Size(max = 100)
	@Email
	@Column(nullable = false, unique = true)
	private String email;

	@NotBlank
	@Size(max = 120)
	@Column(nullable = false)
	private String password;

	@NotBlank
	@Size(max = 50)
	@Column(name = "first_name", nullable = false)
	private String firstName;

	@NotBlank
	@Size(max = 50)
	@Column(name = "last_name", nullable = false)
	private String lastName;

	@Size(max = 20)
	private String phone;

	@Size(max = 100)
	private String company;

	@NotBlank
	@Column(name = "tenant_id", nullable = false)
	private String tenantId;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new HashSet<>();

	@Column(nullable = false)
	private boolean enabled = true;

	@Column(name = "account_non_expired", nullable = false)
	private boolean accountNonExpired = true;

	@Column(name = "account_non_locked", nullable = false)
	private boolean accountNonLocked = true;

	@Column(name = "credentials_non_expired", nullable = false)
	private boolean credentialsNonExpired = true;

	@Column(name = "login_attempts", nullable = false)
	private int loginAttempts = 0;

	@Column(name = "last_login")
	private LocalDateTime lastLogin;

	@Column(name = "password_changed_at")
	private LocalDateTime passwordChangedAt;

	@Column(name = "password_reset_token")
	private String passwordResetToken;

	@Column(name = "password_reset_expires")
	private LocalDateTime passwordResetExpires;

	@Column(name = "email_verification_token")
	private String emailVerificationToken;

	@Column(name = "email_verified", nullable = false)
	private boolean emailVerified = false;

	@CreationTimestamp
	@Column(name = "created_at", updatable = false)
	private LocalDateTime createdAt;

	@UpdateTimestamp
	@Column(name = "updated_at")
	private LocalDateTime updatedAt;

	@Version
	private Long version;

	// Helper methods
	public String getFullName() {
		return firstName + " " + lastName;
	}

	public void incrementLoginAttempts() {
		this.loginAttempts++;
	}

	public void resetLoginAttempts() {
		this.loginAttempts = 0;
	}

	public boolean isLocked() {
		return loginAttempts >= 5;
	}
}
