package com.userSecurity.security.dtorequest;

import lombok.Getter;
import lombok.Setter;
import jakarta.validation.constraints.NotEmpty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UpdateDatePasswordRequest {

    @NotEmpty(message = "Password ID cannot be empty or null")
    private String password;
    @NotEmpty(message = "new password cannot be empty or null")
    private String newPassword;
    @NotEmpty(message = "Confirm password cannot be empty or null")
    private String confirmNewPassword;
}
