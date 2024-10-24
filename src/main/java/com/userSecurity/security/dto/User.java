package com.userSecurity.security.dto;

import lombok.Data;

@Data
public class User {
    private Long id;
    private Long createdBy;
    private Long updatedBY;
    private String userId;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String bio;
    private String imageUri;
    private String qrCodeImageUri;
    private String lastLogin;
    private String createdAt;
    private String updatedAt;
    private String role;
    private String authroteies;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;
    private boolean mfa;

}
