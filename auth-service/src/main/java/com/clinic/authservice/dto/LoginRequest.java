package com.clinic.authservice.dto;


import lombok.Data;
import jakarta.validation.constraints.*;

@Data
public class LoginRequest {

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    public String getEmail() {
        return email;
    }
}
