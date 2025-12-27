package com.clinic.usermanagementservice.controller;

import com.clinic.usermanagementservice.dto.RolesPermissionsResponse;

import com.clinic.usermanagementservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/internal/users")
@RequiredArgsConstructor
public class InternalUserController {

    private final UserService userService;


     // todo  tenantId & authUserId should be from internal token
//    @PostMapping
//    @PreAuthorize("hasAuthority('SCOPE_USER_WRITE')")
//    public UserResponse createInternal(@RequestBody CreateUserRequest req,
//                                       @CurrentUser com.clinic.sharedsecurityjwt.CurrentUser currentUser) {
//        // tenantId & authUserId should be from internal token
//        return userService.createUser(req, currentUser.tenantId(), Long.valueOf(currentUser.userId()));
//    }


    @GetMapping("/{id}/roles-permissions")
    @PreAuthorize("hasAuthority('SCOPE_USER_READ')") // Scope محدد للـ internal services
    public RolesPermissionsResponse getRolesPermissionsInternal(@PathVariable String id) {
        return userService.getRolesPermissions(id);
    }



}


