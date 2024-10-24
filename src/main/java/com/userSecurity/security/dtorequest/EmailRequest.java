package com.userSecurity.security.dtorequest;

import lombok.Setter;
import lombok.Getter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class EmailRequest {

    @NotEmpty(message = "email name cannot be empty or null")
    @Email(message = "Invalid email address")
    private String email;

}
