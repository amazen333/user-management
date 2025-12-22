package com.iotplatform.auth.controller.admin;

import com.iotplatform.auth.dto.CreateUserRequest;
import com.iotplatform.auth.dto.TenantDTO;
import com.iotplatform.auth.dto.UpdateRolesRequest;
import com.iotplatform.auth.dto.UserDTO;
import com.iotplatform.auth.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
@RequiredArgsConstructor
public class AdminController {
    
    private final AdminService adminService;
    
    @GetMapping("/users")
    public ResponseEntity<Page<UserDTO>> getAllUsers(
            @RequestParam(required = false) String tenantId,
            @RequestParam(required = false) String search,
            Pageable pageable) {
        
        Page<UserDTO> users = adminService.getAllUsers(tenantId, search, pageable);
        return ResponseEntity.ok(users);
    }
    
    @GetMapping("/users/{id}")
    public ResponseEntity<UserDTO> getUser(@PathVariable UUID id) {
        UserDTO user = adminService.getUser(id);
        return ResponseEntity.ok(user);
    }
    
    @PostMapping("/users")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<UserDTO> createUser(@RequestBody CreateUserRequest request) {
        UserDTO user = adminService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
    
    @PutMapping("/users/{id}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable UUID id, 
                                              @RequestBody UpdateUserRequest request) {
        UserDTO user = adminService.updateUser(id, request);
        return ResponseEntity.ok(user);
    }
    
    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id) {
        adminService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
    
    @PostMapping("/users/{id}/enable")
    public ResponseEntity<Void> enableUser(@PathVariable UUID id) {
        adminService.enableUser(id);
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/users/{id}/disable")
    public ResponseEntity<Void> disableUser(@PathVariable UUID id) {
        adminService.disableUser(id);
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/users/{id}/unlock")
    public ResponseEntity<Void> unlockUser(@PathVariable UUID id) {
        adminService.unlockUser(id);
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/users/{id}/reset-password")
    public ResponseEntity<Void> resetUserPassword(@PathVariable UUID id) {
        adminService.resetUserPassword(id);
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/users/{id}/roles")
    public ResponseEntity<UserDTO> updateUserRoles(@PathVariable UUID id, 
                                                   @RequestBody UpdateRolesRequest request) {
        UserDTO user = adminService.updateUserRoles(id, request);
        return ResponseEntity.ok(user);
    }
    
    @GetMapping("/tenants")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Page<TenantDTO>> getAllTenants(
            @RequestParam(required = false) String search,
            Pageable pageable) {
        
        Page<TenantDTO> tenants = adminService.getAllTenants(search, pageable);
        return ResponseEntity.ok(tenants);
    }
    
    @PostMapping("/tenants/{id}/activate")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> activateTenant(@PathVariable UUID id) {
        adminService.activateTenant(id);
        return ResponseEntity.ok().build();
    }
    
    @PostMapping("/tenants/{id}/suspend")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> suspendTenant(@PathVariable UUID id) {
        adminService.suspendTenant(id);
        return ResponseEntity.ok().build();
    }
}