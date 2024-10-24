package com.userSecurity.security.validation;

import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.exception.ApiException;

public class UserValidation {

    public static void verifyAccountStatus(UserEntity user) {

        if (!user.isEnabled()) {
            throw new ApiException("Account is disabled");
        }
        if (!user.isAccountNonExpired()) {
            throw new ApiException("Account is expired");
        }
        if (!user.isAccountNonLocked()) {
            throw new ApiException("Account is locked");
        }
    }
}
