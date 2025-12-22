package com.iotplatform.auth.service;

import com.iotplatform.auth.controller.admin.UpdateUserRequest;
import com.iotplatform.auth.dto.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

public interface AdminService {
    
    Page<UserDTO> getAllUsers(String tenantId, String search, Pageable pageable);
    
    UserDTO getUser(UUID userId);
    
    UserDTO createUser(CreateUserRequest request);
    
    UserDTO updateUser(UUID userId, UpdateUserRequest request);
    
    void deleteUser(UUID userId);
    
    void enableUser(UUID userId);
    
    void disableUser(UUID userId);
    
    void unlockUser(UUID userId);
    
    void resetUserPassword(UUID userId);
    
    UserDTO updateUserRoles(UUID userId, UpdateRolesRequest request);
    
    Page<TenantDTO> getAllTenants(String search, Pageable pageable);
    
    void activateTenant(UUID tenantId);
    
    void suspendTenant(UUID tenantId);
}