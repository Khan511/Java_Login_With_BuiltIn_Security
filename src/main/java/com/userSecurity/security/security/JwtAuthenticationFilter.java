package com.userSecurity.security.security;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.core.JsonParser.Feature;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.userSecurity.security.dto.User;
import com.userSecurity.security.dtorequest.LoginRequest;
import com.userSecurity.security.enumeration.LoginType;
import com.userSecurity.security.enumeration.TokenType;
import com.userSecurity.security.service.UserService;

import static com.userSecurity.security.constant.Constant.LOGIN_PATH;
import static com.userSecurity.security.utils.RequestUtils.getResponse;
import static com.userSecurity.security.utils.RequestUtils.handleErrorResponse;
import static org.springframework.http.HttpStatus.OK;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.Map;
import java.util.function.Consumer;

// import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private UserService userService;
    private JwtConfiguration jwtConfiguration;

    // @Autowired
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, UserService userService,
            JwtConfiguration jwtConfiguration) {
        super.setAuthenticationManager(authenticationManager); // Add this line
        setFilterProcessesUrl(LOGIN_PATH);
        this.userService = userService;
        this.jwtConfiguration = jwtConfiguration;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        try {
            var user = new ObjectMapper().configure(Feature.AUTO_CLOSE_SOURCE, true).readValue(request.getInputStream(),
                    LoginRequest.class);

            userService.updateLoginAttempt(user.getEmail(), LoginType.LOGIN_ATTEMPT);

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    user.getEmail(), user.getPassword(),
                    new ArrayList<>());

            return getAuthenticationManager().authenticate(authToken);

        } catch (Exception exception) {
            handleErrorResponse(request, response, exception);

            return null;
        }
        // } catch (StreamReadException e) {
        // throw new RuntimeException(e);
        // } catch (DatabindException e) {
        // throw new RuntimeException(e);
        // } catch (IOException e) {
        // throw new RuntimeException(e);
        // } catch (BadCredentialsException e) {
        // throw new ApiException("Invalid Password!");
        // }

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws StreamReadException, DatabindException, IOException {

        var userDetails = (UserDetails) authResult.getPrincipal();

        // to check account states
        try {
            validAccount.accept(userDetails);
        } catch (Exception e) {
            handleErrorResponse(request, response, e);
            return;
        }

        userService.updateLoginAttempt(userDetails.getUsername(), LoginType.LOGIN_SUCCESS);

        var user = userService.getUserByEmail(userDetails.getUsername());

        var httpResponse = sendResponse(request, response, user);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        response.setStatus(HttpStatus.OK.value());

        var out = response.getOutputStream();

        var mapper = new ObjectMapper();
        mapper.writeValue(out, httpResponse);
        out.flush();
    }

    private Object sendResponse(HttpServletRequest request, HttpServletResponse response, User user) {

        jwtConfiguration.setTokenCookieInResponse(response, user, TokenType.ACCESS);
        jwtConfiguration.setTokenCookieInResponse(response, user, TokenType.REFRESH);

        return getResponse(request, Map.of("user", user), "Login Success", OK);
    }

    // A consumer that validates the user's account status (e.g., locked, disabled,
    // credentials expired, etc.).
    private final Consumer<UserDetails> validAccount = userPrincipal -> {
        // If the account is locked, throw a LockedException.
        if (!userPrincipal.isAccountNonLocked()) {
            throw new LockedException("Your account is currently locked. Please contact the administrator");
        }
        // If the account is disabled, throw a DisabledException.
        if (!userPrincipal.isEnabled()) {
            throw new DisabledException("Your account is currently disabled. Please contact the administrator");
        }
        // If the credentials have expired, throw a CredentialsExpiredException.
        if (!userPrincipal.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("Your password has expired. Please update your password");
        }
        // If the account has expired, throw a DisabledException.
        if (!userPrincipal.isAccountNonExpired()) {
            throw new AccountExpiredException("Your account has expired. Please contact the administrator");
        }
    };
}
