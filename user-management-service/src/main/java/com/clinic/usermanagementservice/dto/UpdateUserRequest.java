package com.clinic.usermanagementservice.dto;

import com.clinic.usermanagementservice.domain.enmus.RoleName;
import com.clinic.usermanagementservice.domain.enmus.UserStatus;
import lombok.Data;

@Data
public class UpdateUserRequest {
    private String fullName;
    private UserStatus status;
    private RoleName roleName;
}
