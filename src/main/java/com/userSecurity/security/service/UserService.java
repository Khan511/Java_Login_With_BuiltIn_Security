package com.userSecurity.security.service;

// import com.userSecurity.security.domain.UserPrincipal;
import com.userSecurity.security.dto.User;
import com.userSecurity.security.entity.RoleEntity;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;
import com.userSecurity.security.enumeration.LoginType;

// import jakarta.servlet.http.HttpServletResponse;

import com.userSecurity.security.entity.CredentialEntity;

public interface UserService {
    void createUser(String firstName, String lastName, String email, String password);

    RoleEntity getRoleName(String name);

    void verifyAccountKey(String key);

    void updateLoginAttempt(String email, LoginType loginType);

    User getUserByUserId(String apply);

    User getUserByEmail(String email);

    // UserPrincipal getUserPrincipalByEmail(String email);

    CredentialEntity getUserCredentialById(Long id);

    User setupMfa(Long id);

    User cancelMfa(Long id);

    User verifyQrCode(String userId, String qrCode);

    void resetPassword(String email);

    User verifyPassword(String token);

    void updatePassword(String userId, String newPassword, String confirmNewPassword);

    User updateUser(String userId, String firstName, String lastName, String email, String phone, String bio);

    void updateRole(String userId, String role);

    void toggleAccountExpired(String userId);

    void toggleAccountLocked(String userId);

    void toggleAccountEnabled(String userId);

    void toggleCredentialExpired(String userId);

    void updatePassword(String userId, String currentPassword, String newPassword, String confirmNewPassword);

    String uploadPhoto(String userId, MultipartFile file);

    User getUserById(Long id);

    List<User> getUsers();

}
