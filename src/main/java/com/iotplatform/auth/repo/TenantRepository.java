package com.iotplatform.auth.repo;

import com.iotplatform.auth.model.Tenant;

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
public interface TenantRepository extends JpaRepository<Tenant, UUID> {
    
    Optional<Tenant> findByTenantId(String tenantId);
    
    Optional<Tenant> findByName(String name);
    
    boolean existsByTenantId(String tenantId);
    
    boolean existsByName(String name);
    
    List<Tenant> findByActiveTrue();
    
    @Query("SELECT t FROM Tenant t WHERE t.subscriptionStatus = 'TRIAL' AND t.trialEndsAt < :now")
    List<Tenant> findExpiredTrials(@Param("now") LocalDateTime now);
    
    @Query("SELECT COUNT(t) FROM Tenant t WHERE t.active = true")
    long countActiveTenants();
    
    @Query("SELECT t FROM Tenant t WHERE " +
           "LOWER(t.name) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(t.contactEmail) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(t.description) LIKE LOWER(CONCAT('%', :search, '%'))")
    List<Tenant> search(@Param("search") String search);

	Page<Tenant> findAll(Specification<Tenant> spec, Pageable pageable);
}