package com.iotplatform.auth.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.iotplatform.auth.controller.admin.UpdateUserRequest;
import com.iotplatform.auth.dto.CreateUserRequest;
import com.iotplatform.auth.dto.TenantDTO;
import com.iotplatform.auth.dto.UpdateRolesRequest;
import com.iotplatform.auth.dto.UserDTO;
import com.iotplatform.auth.exception.EmailAlreadyExistsException;
import com.iotplatform.auth.exception.RoleNotFoundException;
import com.iotplatform.auth.exception.TenantLimitExceededException;
import com.iotplatform.auth.exception.TenantNotFoundException;
import com.iotplatform.auth.exception.UnauthorizedException;
import com.iotplatform.auth.mapper.UserMapper;
import com.iotplatform.auth.exception.UserNotFoundException;
import com.iotplatform.auth.exception.UsernameAlreadyExistsException;
import com.iotplatform.auth.model.Role;
import com.iotplatform.auth.model.Tenant;
import com.iotplatform.auth.model.User;
import com.iotplatform.auth.repo.TenantRepository;
import com.iotplatform.auth.repo.UserRepository;
import com.iotplatform.auth.repo.*;

import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminServiceImpl implements AdminService {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TenantRepository tenantRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    
    @Override
    @Transactional(readOnly = true)
    public Page<UserDTO> getAllUsers(String tenantId, String search, Pageable pageable) {
        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            
            if (tenantId != null && !tenantId.isEmpty()) {
                predicates.add(cb.equal(root.get("tenantId"), tenantId));
            }
            
            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                Predicate usernamePred = cb.like(cb.lower(root.get("username")), searchPattern);
                Predicate emailPred = cb.like(cb.lower(root.get("email")), searchPattern);
                Predicate firstNamePred = cb.like(cb.lower(root.get("firstName")), searchPattern);
                Predicate lastNamePred = cb.like(cb.lower(root.get("lastName")), searchPattern);
                predicates.add(cb.or(usernamePred, emailPred, firstNamePred, lastNamePred));
            }
            
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        
        Page<User> users = userRepository.findAll(spec, pageable);
        return users.map(userMapper::toDTO);
    }
    
    @Override
    @Transactional(readOnly = true)
    public UserDTO getUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional
    public UserDTO createUser(CreateUserRequest request) {
        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UsernameAlreadyExistsException("Username is already taken");
        }
        
        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email is already in use");
        }
        
        // Verify tenant exists
        Tenant tenant = tenantRepository.findByTenantId(request.getTenantId())
            .orElseThrow(() -> new TenantNotFoundException("Tenant not found"));
        
        // Check tenant user limit
        long userCount = userRepository.countByTenantId(request.getTenantId());
        if (tenant.getMaxUsers() != null && userCount >= tenant.getMaxUsers()) {
            throw new TenantLimitExceededException("Tenant user limit reached");
        }
        
        // Create user
        User user = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .phone(request.getPhone())
            .company(request.getCompany())
            .tenantId(request.getTenantId())
            .passwordChangedAt(LocalDateTime.now())
            .emailVerified(true) // Admin created users are automatically verified
            .build();
        
        // Assign roles
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            Set<Role> roles = new HashSet<>();
            for (String roleName : request.getRoles()) {
                Role.RoleName roleEnum;
                try {
                    roleEnum = Role.RoleName.valueOf(roleName);
                } catch (IllegalArgumentException e) {
                    throw new RoleNotFoundException("Invalid role: " + roleName);
                }
                
                Role role = roleRepository.findByName(roleEnum)
                    .orElseThrow(() -> new RoleNotFoundException("Role not found: " + roleName));
                roles.add(role);
            }
            user.setRoles(roles);
        } else {
            // Assign default user role
            Role userRole = roleRepository.findByName(Role.RoleName.ROLE_USER)
                .orElseThrow(() -> new RoleNotFoundException("User role not found"));
            user.getRoles().add(userRole);
        }
        
        user = userRepository.save(user);
        
        // Send welcome email if requested
        if (request.isSendWelcomeEmail()) {
            emailService.sendWelcomeEmail(user.getEmail(), user.getUsername(), tenant.getName());
        }
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional
    public UserDTO updateUser(UUID userId, UpdateUserRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        // Update email if changed
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
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
        
        // Update other fields
        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        
        if (request.getCompany() != null) {
            user.setCompany(request.getCompany());
        }
        
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }
        
        if (request.getRoles() != null) {
            Set<Role> roles = new HashSet<>();
            for (String roleName : request.getRoles()) {
                Role.RoleName roleEnum;
                try {
                    roleEnum = Role.RoleName.valueOf(roleName);
                } catch (IllegalArgumentException e) {
                    throw new RoleNotFoundException("Invalid role: " + roleName);
                }
                
                Role role = roleRepository.findByName(roleEnum)
                    .orElseThrow(() -> new RoleNotFoundException("Role not found: " + roleName));
                roles.add(role);
            }
            user.setRoles(roles);
        }
        
        user = userRepository.save(user);
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        // Don't allow deleting super admin users
        boolean isSuperAdmin = user.getRoles().stream()
            .anyMatch(role -> role.getName() == Role.RoleName.ROLE_SUPER_ADMIN);
        
        if (isSuperAdmin) {
            throw new UnauthorizedException("Cannot delete super admin users");
        }
        
        userRepository.delete(user);
        
        log.info("User deleted: {} by admin", user.getUsername());
    }
    
    @Override
    @Transactional
    public void enableUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        user.setEnabled(true);
        userRepository.save(user);
        
        log.info("User enabled: {} by admin", user.getUsername());
    }
    
    @Override
    @Transactional
    public void disableUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        // Don't allow disabling super admin users
        boolean isSuperAdmin = user.getRoles().stream()
            .anyMatch(role -> role.getName() == Role.RoleName.ROLE_SUPER_ADMIN);
        
        if (isSuperAdmin) {
            throw new UnauthorizedException("Cannot disable super admin users");
        }
        
        user.setEnabled(false);
        userRepository.save(user);
        
        log.info("User disabled: {} by admin", user.getUsername());
    }
    
    @Override
    @Transactional
    public void unlockUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        user.resetLoginAttempts();
        user.setAccountNonLocked(true);
        userRepository.save(user);
        
        log.info("User unlocked: {} by admin", user.getUsername());
    }
    
    @Override
    @Transactional
    public void resetUserPassword(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        // Generate temporary password
        String tempPassword = generateTemporaryPassword();
        user.setPassword(passwordEncoder.encode(tempPassword));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);
        
        // Send password reset email
        emailService.sendAdminPasswordResetEmail(user.getEmail(), user.getUsername(), tempPassword);
        
        log.info("Password reset for user: {} by admin", user.getUsername());
    }
    
    @Override
    @Transactional
    public UserDTO updateUserRoles(UUID userId, UpdateRolesRequest request) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        
        Set<Role> roles = new HashSet<>();
        for (String roleName : request.getRoles()) {
            Role.RoleName roleEnum;
            try {
                roleEnum = Role.RoleName.valueOf(roleName);
            } catch (IllegalArgumentException e) {
                throw new RoleNotFoundException("Invalid role: " + roleName);
            }
            
            Role role = roleRepository.findByName(roleEnum)
                .orElseThrow(() -> new RoleNotFoundException("Role not found: " + roleName));
            roles.add(role);
        }
        
        user.setRoles(roles);
        user = userRepository.save(user);
        
        log.info("User roles updated: {} by admin", user.getUsername());
        
        return userMapper.toDTO(user);
    }
    
    @Override
    @Transactional(readOnly = true)
    public Page<TenantDTO> getAllTenants(String search, Pageable pageable) {
        Specification<Tenant> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            
            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                Predicate namePred = cb.like(cb.lower(root.get("name")), searchPattern);
                Predicate emailPred = cb.like(cb.lower(root.get("contactEmail")), searchPattern);
                Predicate descPred = cb.like(cb.lower(root.get("description")), searchPattern);
                predicates.add(cb.or(namePred, emailPred, descPred));
            }
            
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        
        Page<Tenant> tenants = tenantRepository.findAll(spec, pageable);
        
        return tenants.map(tenant -> {
            Long userCount = userRepository.countByTenantId(tenant.getTenantId());
            
            return TenantDTO.builder()
                .id(tenant.getId().toString())
                .name(tenant.getName())
                .tenantId(tenant.getTenantId())
                .description(tenant.getDescription())
                .contactEmail(tenant.getContactEmail())
                .contactPhone(tenant.getContactPhone())
                .company(tenant.getCompany())
                .address(tenant.getAddress())
                .city(tenant.getCity())
                .state(tenant.getState())
                .postalCode(tenant.getPostalCode())
                .country(tenant.getCountry())
                .maxUsers(tenant.getMaxUsers())
                .maxDevices(tenant.getMaxDevices())
                .subscriptionPlan(tenant.getSubscriptionPlan())
                .subscriptionStatus(tenant.getSubscriptionStatus().name())
                .trialEndsAt(tenant.getTrialEndsAt())
                .active(tenant.isActive())
                .createdAt(tenant.getCreatedAt())
                .updatedAt(tenant.getUpdatedAt())
                .userCount(userCount)
                .build();
        });
    }
    
    @Override
    @Transactional
    public void activateTenant(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
            .orElseThrow(() -> new TenantNotFoundException("Tenant not found"));
        
        tenant.setActive(true);
        tenant.setSubscriptionStatus(Tenant.SubscriptionStatus.ACTIVE);
        tenantRepository.save(tenant);
        
        log.info("Tenant activated: {}", tenant.getName());
    }
    
    @Override
    @Transactional
    public void suspendTenant(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
            .orElseThrow(() -> new TenantNotFoundException("Tenant not found"));
        
        tenant.setActive(false);
        tenant.setSubscriptionStatus(Tenant.SubscriptionStatus.SUSPENDED);
        tenantRepository.save(tenant);
        
        log.info("Tenant suspended: {}", tenant.getName());
    }
    
    // Helper methods
    private String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }
    
    private String generateTemporaryPassword() {
        // Generate a random 10-character alphanumeric password
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        
        for (int i = 0; i < 10; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return sb.toString();
    }

	
}