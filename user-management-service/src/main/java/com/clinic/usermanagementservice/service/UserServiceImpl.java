package com.clinic.usermanagementservice.service;

import com.clinic.sharedsecurityjwt.UserPrincipal;
import com.clinic.usermanagementservice.domain.Role;
import com.clinic.usermanagementservice.domain.User;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import com.clinic.usermanagementservice.dto.CreateUserRequest;
import com.clinic.usermanagementservice.dto.RolePermissionRow;
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
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    /**
     * Create user linked to authUser and tenant.
     *
     * @param request DTO from onboarding
     * @return created user response
     */
    @Override
    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        // 1️⃣ Map DTO to User entity

        if (userRepository.existsByTenantIdAndEmail(request.getTenantId(), request.getEmail())) {
            throw new IllegalArgumentException(
                    "User already exists with email: " + request.getEmail() + " for tenant: " + request.getTenantId()
            );
        }

        User user = new User();

        user.setEmail(request.getEmail());

        user.setFullName(request.getFullName());

        // 2️⃣ Set tenantId and authUserId
        user.setTenantId(request.getTenantId());
        user.setAuthUserId(request.getAuthUserId());

        // 3️⃣ Find Role by roleName
        Role role = roleRepository.findByName(request.getRoleName())
                .orElseThrow(() -> new IllegalArgumentException("Role not found: " + request.getRoleName()));
        user.setRole(role);

        // 4️⃣ Save user
        User savedUser = userRepository.save(user);


        UserResponse response = UserResponse.builder()
             .id(savedUser.getId())
                .email(savedUser.getEmail())
                .fullName(savedUser.getFullName())
                .status(savedUser.getStatus().name())
                .roleName(savedUser.getRole().getName()).build();


        return response;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> searchUsers(String email, String fullName, UserStatus status, Pageable pageable) {
        Specification<User> spec = UserSpecification.filterBy(email, fullName, status);
        return userRepository.findAll(spec, pageable)
                .map(this::mapToResponse);
    }

    @Override
    public UserResponse getCurrentUser(UserPrincipal currentUser) {
        User user = userRepository.findByAuthUserIdAndTenantId(Long.valueOf(currentUser.getSub()), currentUser.tenantId())
                .orElseThrow(() -> new RuntimeException("User not found"));
        return mapToResponse(user);
    }

    private UserResponse mapToResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .status(user.getStatus().name())
                .roleName(user.getRole() != null ? user.getRole().getName() : null)
                .build();
    }


    @Transactional(readOnly = true)
    @Override
    public RolesPermissionsResponse getRolesPermissions(String userId) {

        List<RolePermissionRow> rows =
                userRepository.findRolePermissionRows(Long.valueOf(userId));

        if (rows.isEmpty()) {
            throw new IllegalArgumentException("User has no role or permissions");
        }

        String role = rows.get(0).role();

        Set<String> permissions = rows.stream()
                .map(RolePermissionRow::permission)
                .collect(Collectors.toUnmodifiableSet());

        return new RolesPermissionsResponse(role, permissions);
    }



}
