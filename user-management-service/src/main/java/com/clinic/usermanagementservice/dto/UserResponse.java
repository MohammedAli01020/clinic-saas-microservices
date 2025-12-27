package com.clinic.usermanagementservice.dto;

import com.clinic.usermanagementservice.domain.enmus.RoleName;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserResponse {
    private Long id;
    private String email;
    private String fullName;
    private UserStatus status;
    private RoleName roleName;
}
