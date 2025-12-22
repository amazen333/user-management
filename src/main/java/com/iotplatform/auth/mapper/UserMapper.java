package com.iotplatform.auth.mapper;

import java.util.List;
import java.util.stream.Collectors;

import org.mapstruct.*;
import org.mapstruct.Mapping;


import com.iotplatform.auth.dto.UserDTO;
import com.iotplatform.auth.model.User;

@Mapper(componentModel = "spring", 
        unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {
    
    @Mapping(target = "roles", expression = "java(mapRoles(user))")
    UserDTO toDTO(User user);
    
    List<UserDTO> toDTOList(List<User> users);
    
    default List<String> mapRoles(User user) {
        return user.getRoles().stream()
            .map(role -> role.getName().name())
            .collect(Collectors.toList());
    }
}