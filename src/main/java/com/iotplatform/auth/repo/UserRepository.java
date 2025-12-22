package com.iotplatform.auth.repo;

import com.iotplatform.auth.model.User;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByUsernameOrEmail(String username, String email);
    
    Boolean existsByUsername(String username);
    
    Boolean existsByEmail(String email);
    
    List<User> findByTenantId(String tenantId);
    
    List<User> findByTenantIdAndEnabledTrue(String tenantId);
    
    @Query("SELECT u FROM User u WHERE u.tenantId = :tenantId AND " +
           "(LOWER(u.username) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :search, '%')))")
    List<User> search(@Param("tenantId") String tenantId, 
                      @Param("search") String search);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.tenantId = :tenantId")
    long countByTenantId(@Param("tenantId") String tenantId);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.tenantId = :tenantId AND u.enabled = true")
    long countActiveUsersByTenantId(@Param("tenantId") String tenantId);
    
    Optional<User> findByPasswordResetToken(String token);
    
    Optional<User> findByEmailVerificationToken(String token);
    
    @Query("SELECT u FROM User u WHERE u.lastLogin < :cutoff AND u.enabled = true")
    List<User> findInactiveUsers(@Param("cutoff") LocalDateTime cutoff);
    
    @Query("SELECT u FROM User u WHERE u.accountNonLocked = false")
    List<User> findLockedUsers();

	Page<User> findAll(Specification<User> spec, Pageable pageable);
}