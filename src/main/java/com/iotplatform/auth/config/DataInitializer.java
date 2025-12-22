package com.iotplatform.auth.config;

import com.iotplatform.auth.model.Role;
import com.iotplatform.auth.model.Tenant;
import com.iotplatform.auth.model.User;
import com.iotplatform.auth.repo.RoleRepository;
import com.iotplatform.auth.repo.TenantRepository;
import com.iotplatform.auth.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {
    
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Bean
    public CommandLineRunner initData() {
        return args -> {
            // Initialize roles
            initRoles();
            
            // Initialize default admin tenant and user
            initDefaultAdmin();
            
            log.info("Data initialization completed");
        };
    }
    
    private void initRoles() {
        // Create roles if they don't exist
        for (Role.RoleName roleName : Role.RoleName.values()) {
            if (!roleRepository.existsByName(roleName)) {
                Role role = Role.builder()
                    .name(roleName)
                    .description(getRoleDescription(roleName))
                    .build();
                roleRepository.save(role);
                log.info("Created role: {}", roleName);
            }
        }
    }
    
    private void initDefaultAdmin() {
        // Create default admin tenant if it doesn't exist
        if (!tenantRepository.existsByTenantId("admin")) {
            Tenant adminTenant = Tenant.builder()
                .name("Administration")
                .tenantId("admin")
                .description("System administration tenant")
                .contactEmail("admin@iotplatform.com")
                .maxUsers(100)
                .maxDevices(1000)
                .subscriptionPlan("ENTERPRISE")
                .subscriptionStatus(Tenant.SubscriptionStatus.ACTIVE)
                .active(true)
                .build();
            
            tenantRepository.save(adminTenant);
            log.info("Created admin tenant");
        }
        
        // Create super admin user if it doesn't exist
        if (!userRepository.existsByUsername("admin")) {
            Tenant adminTenant = tenantRepository.findByTenantId("admin")
                .orElseThrow(() -> new RuntimeException("Admin tenant not found"));
            
            User adminUser = User.builder()
                .username("admin")
                .email("admin@iotplatform.com")
                .password(passwordEncoder.encode("Admin@123"))
                .firstName("System")
                .lastName("Administrator")
                .tenantId(adminTenant.getTenantId())
                .passwordChangedAt(LocalDateTime.now())
                .emailVerified(true)
                .build();
            
            // Assign all roles to admin
            Set<Role> allRoles = new HashSet<>(roleRepository.findAll());
            adminUser.setRoles(allRoles);
            
            userRepository.save(adminUser);
            log.info("Created super admin user");
        }
    }
    
    private String getRoleDescription(Role.RoleName roleName) {
        switch (roleName) {
            case ROLE_SUPER_ADMIN:
                return "Full system access with all privileges";
            case ROLE_ADMIN:
                return "Tenant administrator with full tenant access";
            case ROLE_USER:
                return "Standard user with basic privileges";
            case ROLE_VIEWER:
                return "Read-only access to system resources";
            case ROLE_API_CLIENT:
                return "API client with programmatic access";
            default:
                return "System role";
        }
    }
}