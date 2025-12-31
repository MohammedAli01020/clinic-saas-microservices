package com.clinic.usermanagementservice.controller;

import com.clinic.usermanagementservice.dto.CreateUserRequest;
import com.clinic.usermanagementservice.dto.RolesPermissionsResponse;

import com.clinic.usermanagementservice.dto.UserResponse;
import com.clinic.usermanagementservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/internal/users")
@RequiredArgsConstructor
public class InternalUserController {

    private final UserService userService;

    /**
     * Create a new User from an internal service.
     * tenantId and authUserId come from internal token (SecurityPrincipal)
     */
    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_USER_WRITE')") // Scope خاص بالـ internal services
    public UserResponse createInternal(
            @RequestBody CreateUserRequest req
    ) {

//        Long authUserId = Long.valueOf(principal.sub()); // ID بتاع auth user اللي عامل onboarding

        return userService.createUser(req);
    }


    @GetMapping("/{id}/roles-permissions")
    @PreAuthorize("hasAuthority('SCOPE_USER_READ')") // Scope محدد للـ internal services
    public RolesPermissionsResponse getRolesPermissionsInternal(@PathVariable("id") String id) {
        return userService.getRolesPermissions(id);
    }



}


