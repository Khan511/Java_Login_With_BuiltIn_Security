package com.userSecurity.security.dtorequest;

import lombok.Data;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginRequest {
    @NotEmpty(message = "email name cannot be empty or null")
    @Email(message = "Invalid email address")
    private String email;
    @NotEmpty(message = "password cannot be empty or null")
    private String password;
}
