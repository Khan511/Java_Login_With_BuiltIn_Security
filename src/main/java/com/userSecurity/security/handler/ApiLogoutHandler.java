package com.userSecurity.security.handler;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import com.userSecurity.security.security.JwtConfiguration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Service
@RequiredArgsConstructor
public class ApiLogoutHandler implements LogoutHandler {

    private final JwtConfiguration jwtConfiguration;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        jwtConfiguration.removeTokenCookies(response);

    }
}
