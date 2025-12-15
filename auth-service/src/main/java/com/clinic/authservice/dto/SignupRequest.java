package com.clinic.authservice.dto;

import lombok.Data;
import jakarta.validation.constraints.*;

@Data
public class SignupRequest {

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    @NotBlank
    private String tenantId;

}
