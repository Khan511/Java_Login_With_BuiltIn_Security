package com.userSecurity.security.security;

import static com.userSecurity.security.enumeration.TokenType.ACCESS;
import static com.userSecurity.security.utils.RequestUtils.handleErrorResponse;

import java.io.IOException;
import java.util.Objects;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.userSecurity.security.domain.RequestContext;
import com.userSecurity.security.domain.Token;
import com.userSecurity.security.domain.TokenData;
import com.userSecurity.security.enumeration.TokenType;
// import com.userSecurity.security.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtConfiguration jwtConfiguration;
    private final UserDetailsService userDetailsService;

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // Extract the access token from the request using the jwtConfiguration.
            var accessToken = jwtConfiguration.getTokenFromRequestCookie(request, TokenType.ACCESS.getValue());

            // Check if the access token is present and valid.
            if (accessToken.isPresent() && jwtConfiguration.extractTokenData(accessToken.get(), TokenData::isValid)) {
                // If valid, set the authentication context with the user's details.
                SecurityContextHolder.getContext().setAuthentication(getAuthentication(accessToken.get(), request));

                Long userId = jwtConfiguration.extractTokenData(accessToken.get(), TokenData::getUser).getId();

                // Set the user ID in the RequestContext for further use in the request
                // lifecycle.
                RequestContext.setUserId(userId);
            } else {
                // If the access token is not present or invalid, try to extract the refresh
                // token.
                var refreshToken = jwtConfiguration.getTokenFromRequestCookie(request, TokenType.REFRESH.getValue());

                // Check if the refresh token is present and valid.
                if (refreshToken.isPresent()
                        && jwtConfiguration.extractTokenData(refreshToken.get(), TokenData::isValid)) {
                    // Extract the user details from the refresh token.
                    var user = jwtConfiguration.extractTokenData(refreshToken.get(), TokenData::getUser);

                    // Create a new access token for the user and set the authentication context.
                    SecurityContextHolder.getContext().setAuthentication(
                            getAuthentication(jwtConfiguration.generateTokenForUser(user,
                                    Token::getAccess), request));

                    // Add the new access token as a cookie in the response.
                    jwtConfiguration.setTokenCookieInResponse(response, user, ACCESS);
                    // Set the user ID in the RequestContext.
                    RequestContext.setUserId(user.getId());

                } else {
                    // If neither access nor refresh tokens are valid, clear the security context to
                    // prevent access.
                    SecurityContextHolder.clearContext();
                }
            }
            // Continue the filter chain to allow the request to proceed to the next filter
            // or resource.
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            // If an exception occurs, log the error and handle the error response.
            log.error(e.getMessage());
            handleErrorResponse(request, response, e);
        }

    }

    private UsernamePasswordAuthenticationToken getAuthentication(String token, HttpServletRequest request) {

        if (Objects.nonNull(token)) {

            // Extract the email from the token
            String email = jwtConfiguration.extractEmailFromToken(token);

            if (Objects.nonNull(email)) {
                // Load user details using the email
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                // Check if the token is valid
                if (jwtConfiguration.validateToken(token, userDetails)) {
                    // If valid, create and return the UsernamePasswordAuthenticationToken
                    return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                }
            }
        }
        return null; // Return null if the token is not valid or email is null
    }

}
