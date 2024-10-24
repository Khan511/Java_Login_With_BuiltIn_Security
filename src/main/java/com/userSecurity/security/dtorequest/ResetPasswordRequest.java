package com.userSecurity.security.dtorequest;

import lombok.Getter;
import lombok.Setter;
import jakarta.validation.constraints.NotEmpty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class ResetPasswordRequest {
    @NotEmpty(message = "User ID cannot be empty or null")
    private String userId;

    @NotEmpty(message = "password cannot be empty or null")
    private String newPassword;
    
    @NotEmpty(message = "Confirm password cannot be empty or null")
    private String confirmNewPassword;

}
