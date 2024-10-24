package com.userSecurity.security.security;

import java.util.List;
import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import com.userSecurity.security.entity.CredentialEntity;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.exception.ApiException;
import com.userSecurity.security.repository.UserRepository;
import com.userSecurity.security.service.UserService;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class UserDetailsServiceConfig {

    private final UserService userService;

    @Bean
    public UserDetailsService userDetialsService(UserRepository userRepository) {

        return email -> {
            // Fetch User
            Optional<UserEntity> userOptional = userRepository.findByEmailIgnoreCase(email);
            if (!userOptional.isPresent()) {
                throw new ApiException("User not found");
            }
            UserEntity userEntity = userOptional.get();

            CredentialEntity credentialEntity = userService.getUserCredentialById(userEntity.getId());

            // Convert roles/authorities to GrantedAuthority, if needed
            GrantedAuthority authority = new SimpleGrantedAuthority(userEntity.getRole().getName());
            List<GrantedAuthority> authorities = List.of(authority);

            return new org.springframework.security.core.userdetails.User(userEntity.getEmail(),
                    credentialEntity.getPassword(), authorities);
        };
    }
}
