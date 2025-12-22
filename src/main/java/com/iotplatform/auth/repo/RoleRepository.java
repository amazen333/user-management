package com.iotplatform.auth.repo;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.iotplatform.auth.model.Role;
import com.iotplatform.auth.model.Role.RoleName;

public interface RoleRepository extends JpaRepository<Role, Long> {
	List<Role> findAll();

	boolean existsByName(RoleName roleName);

	Role save(Role role);

}
