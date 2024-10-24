package com.userSecurity.security.dtorequest;

import lombok.Setter;
import lombok.Getter;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserRequest {
    @NotEmpty(message = "First name cannot be empty or null")
    private String firstName;
    @NotEmpty(message = "Last name cannot be empty or null")
    private String lastName;
    @NotEmpty(message = "email name cannot be empty or null")
    @Email(message = "Invalid email address")
    private String email;
    @NotEmpty(message = "password cannot be empty or null")
    private String password;
    private String phone;
    private String bio;
}
