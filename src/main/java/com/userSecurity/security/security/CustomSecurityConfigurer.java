package com.userSecurity.security.security;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import com.userSecurity.security.service.UserService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

@Component
@RequiredArgsConstructor
public class CustomSecurityConfigurer extends AbstractHttpConfigurer<CustomSecurityConfigurer, HttpSecurity> {

    // The JwtAuthorizationFilter handles JWT token validation and authorization.
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    // JwtService handles operations related to JWTs, such as token creation and
    // validation.
    private final JwtConfiguration jwtService;

    // UserService is used to perform user-related operations, such as fetching user
    // details.
    private final UserService userService;

    // AuthenticationConfiguration provides access to the AuthenticationManager,
    // which handles authentication.
    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);

        http.addFilterAfter(new JwtAuthenticationFilter(authenticationConfiguration.getAuthenticationManager(),
                userService, jwtService), UsernamePasswordAuthenticationFilter.class);
    }
}
