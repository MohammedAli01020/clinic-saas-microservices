package com.clinic.usermanagementservice.service;

import com.clinic.usermanagementservice.domain.Permission;
import com.clinic.usermanagementservice.domain.Role;
import com.clinic.usermanagementservice.domain.User;
import com.clinic.usermanagementservice.domain.enmus.RoleName;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import com.clinic.usermanagementservice.dto.CreateUserRequest;
import com.clinic.usermanagementservice.dto.RolesPermissionsResponse;
import com.clinic.usermanagementservice.dto.UserResponse;
import com.clinic.usermanagementservice.repository.RoleRepository;
import com.clinic.usermanagementservice.repository.UserRepository;
import com.clinic.usermanagementservice.specification.UserSpecification;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;
    private final RoleRepository roleRepository;

    public UserResponse createUser(CreateUserRequest req, String tenantId, Long authUserId) {
        Role role = roleRepository.findByName(req.getRoleName().name())
                .orElseThrow(() -> new RuntimeException("Role not found"));

        User user = User.builder()
                .authUserId(authUserId)
                .email(req.getEmail())
                .fullName(req.getFullName())
                .role(role)
                .status(UserStatus.ACTIVE)
                .tenantId(tenantId)
                .build();

        repository.save(user);

        return mapToResponse(user);
    }

    public Page<UserResponse> searchUsers(String email, String fullName, UserStatus status, Pageable pageable) {
        Specification<User> spec = UserSpecification.filterBy(email, fullName, status);
        return repository.findAll(spec, pageable)
                .map(this::mapToResponse);
    }

//    public UserResponse getCurrentUser(CurrentUser currentUser) {
//        User user = repository.findByAuthUserIdAndTenantId(Long.valueOf(currentUser.userId()), currentUser.tenantId())
//                .orElseThrow(() -> new RuntimeException("User not found"));
//        return mapToResponse(user);
//    }

    private UserResponse mapToResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .status(user.getStatus())
                .roleName(user.getRole() != null ? RoleName.valueOf(user.getRole().getName()) : null)
                .build();
    }


    public RolesPermissionsResponse getRolesPermissions(String userId) {

        User user = repository.findById(Long.valueOf(userId))
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));


        Set<String> permissions = user.getRole().getPermissions()
                .stream()
                .map(Permission::getName)
                .collect(Collectors.toUnmodifiableSet());

        return new RolesPermissionsResponse(user.getRole().getName(), permissions);
    }

}
