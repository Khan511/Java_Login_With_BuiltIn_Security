package com.userSecurity.security.service;

import org.mockito.Mock;
import java.util.Optional;
import java.time.LocalDateTime;
import org.mockito.InjectMocks;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import com.userSecurity.security.entity.RoleEntity;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.enumeration.Authority;
import static org.assertj.core.api.Assertions.assertThat; // <-- Add this import
import com.userSecurity.security.entity.CredentialEntity;
import com.userSecurity.security.repository.UserRepository;
import com.userSecurity.security.service.impl.UserServiceImpl;
import com.userSecurity.security.repository.CredentialRepository;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {
    @Mock
    private UserRepository userRepository;
    @Mock
    private CredentialRepository credentialRepository;
    @InjectMocks
    private UserServiceImpl userServiceImpl;

    @Test
    @DisplayName("Test find user by ID")
    public void getUserByUserIdTest() {
        // Arrange - Given
        var userEntity = new UserEntity();
        userEntity.setFirstName("Naji");
        userEntity.setId(1L);
        userEntity.setUserId("1");
        userEntity.setCreatedAt(LocalDateTime.of(1992, 12, 03, 1, 12, 20));
        userEntity.setUpdatedAt(LocalDateTime.of(1992, 12, 03, 1, 12, 20));
        userEntity.setLastLogin(LocalDateTime.of(1992, 12, 03, 1, 12, 20));

        var roleEntity = new RoleEntity("USER", Authority.USER);
        userEntity.setRole(roleEntity);

        var credentialEntity = new CredentialEntity();
        credentialEntity.setCreatedAt(LocalDateTime.of(1992, 12, 03, 1, 12, 20));
        credentialEntity.setUpdatedAt(LocalDateTime.of(1992, 12, 03, 1, 12, 20));
        credentialEntity.setPassword("password");
        credentialEntity.setUserEntity(userEntity);

        when(userRepository.findUserByUserId("1")).thenReturn(Optional.of(userEntity));
        when(credentialRepository.getCredentialByUserEntityId(1L)).thenReturn(Optional.of(credentialEntity));

        // Act - When
        var userByUserId = userServiceImpl.getUserByUserId("1");
        // Assert - Then
        assertThat(userByUserId.getFirstName()).isEqualTo(userEntity.getFirstName());
        assertThat(userByUserId.getUserId()).isEqualTo("1");
    }
}
