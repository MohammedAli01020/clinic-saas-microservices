package com.clinic.usermanagementservice.controller;

import com.clinic.sharedsecurityjwt.annotation.CurrentUser;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import com.clinic.usermanagementservice.dto.CreateUserRequest;
import com.clinic.usermanagementservice.dto.UserResponse;
import com.clinic.usermanagementservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

//    @PostMapping
//    @PreAuthorize("hasAuthority('user.write')")
//    public UserResponse create(@RequestBody CreateUserRequest req, @CurrentUser com.clinic.sharedsecurityjwt.CurrentUser currentUser) {
//        return userService.createUser(req, currentUser.tenantId(), Long.valueOf(currentUser.userId()));
//    }

    @GetMapping
    @PreAuthorize("hasAuthority('user.read')")
    public Page<UserResponse> search(
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String fullName,
            @RequestParam(required = false) UserStatus status,
            Pageable pageable
    ) {
        return userService.searchUsers(email, fullName, status, pageable);
    }

//    @GetMapping("/me")
//    public UserResponse getCurrentUser(@CurrentUser com.clinic.sharedsecurityjwt.CurrentUser currentUser) {
//        return userService.getCurrentUser(currentUser);
//    }
}
