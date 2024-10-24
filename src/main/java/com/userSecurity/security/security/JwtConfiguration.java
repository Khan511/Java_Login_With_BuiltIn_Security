package com.userSecurity.security.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import javax.crypto.SecretKey;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;
import com.google.common.base.Function;
import com.userSecurity.security.domain.Token;
import com.userSecurity.security.domain.TokenData;
import com.userSecurity.security.dto.User;
import com.userSecurity.security.enumeration.TokenType;
import com.userSecurity.security.function.TriConsumer;
import com.userSecurity.security.service.UserService;
import static com.userSecurity.security.constant.Constant.AUTHORITIES;
import static com.userSecurity.security.constant.Constant.AUTHORITY_DELIMITER;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import static com.userSecurity.security.constant.Constant.GET_ARRAYS_LLC;
import static com.userSecurity.security.constant.Constant.ROLE;
import static com.userSecurity.security.constant.Constant.ROLE_PREFIX;
import static com.userSecurity.security.enumeration.TokenType.ACCESS;
import static com.userSecurity.security.enumeration.TokenType.REFRESH;
import static org.springframework.boot.web.server.Cookie.SameSite.NONE;
import static java.util.Arrays.stream;

/**
 * JwtConfiguration
 */
@Slf4j
@Getter
@Setter
@Component
@RequiredArgsConstructor
public class JwtConfiguration {

    // // @Value("${jwt.expiration}")
    // @Value("${JWT_EXPIRATION}")
    // private Long expiration;
    // @Value("${jwt.expiration}")
    @Value("${JWT_ACCESS_TOKEN_EXPIRATION}")
    private Long accessTokenExpiration;
    // @Value("${jwt.expiration}")
    @Value("${JWT_REFRESH_TOKEN_EXPIRATION}")
    private Long refreshTokenExpiration;

    // @Value("${jwt.secret}")
    @Value("${JWT_SECRET}")
    private String secret;

    private final UserService userService;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public Claims parseTokenClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private JwtBuilder jwtBuilder() {
        return Jwts.builder()
                // .setHeader().add(Map.of(Header.TYPE, Header.JWT_TYPE)) // Add the JWT header.
                .setHeader(Map.of(Header.TYPE, Header.JWT_TYPE)) // Add the JWT header.
                .setAudience(GET_ARRAYS_LLC) // Add the audience claim.
                .setId(UUID.randomUUID().toString()) // Set a unique ID for the token.
                .setIssuedAt(Date.from(Instant.now())) // Set the token's issue date.
                .setNotBefore(new Date()) // Set the not-before date to the current time.
                .signWith(getSigningKey(), SignatureAlgorithm.HS512);
    }

    // Function to build an access or refresh token based on the TokenType.
    private String generateToken(User user, TokenType type) {

        return Objects.equals(type, ACCESS)
                ? jwtBuilder()
                        .setSubject(user.getUserId()) // Set the subject to the user ID.
                        .claim(AUTHORITIES, user.getAuthroteies()) // Add authorities claim.
                        .claim(ROLE, user.getRole()) // Add role claim.
                        .claim("email", user.getEmail())
                        // Set the expiration time.
                        .setExpiration(Date.from(Instant.now().plusSeconds(
                                accessTokenExpiration)))
                        .compact() // Build and compact the token into a string.
                : jwtBuilder()
                        .setSubject(user.getUserId()) // Set the subject to the user ID.
                        // Set the expiration time.
                        .setExpiration(Date.from(Instant.now().plusSeconds(
                                refreshTokenExpiration)))
                        .compact();
    } // Build and compact the token into a string.

    private Claims extrAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extrAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String extractSubjectFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractEmailFromToken(String token) {
        return extractClaim(token, (claims -> claims.get("email", String.class)));
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // TriConsumer to add a cookie to the HTTP response with the JWT (access or
    // refresh token).
    private final TriConsumer<HttpServletResponse, User, TokenType> tokenCookieSetter = (response, user, type) -> {

        // Switch statement to handle different token types (ACCESS and REFRESH).
        switch (type) {

            case ACCESS -> {

                var accessToken = generateTokenForUser(user, Token::getAccess); // Create an access token.
                var cookie = new Cookie(type.getValue(), accessToken); // Create a new cookie with the token.
                cookie.setHttpOnly(true); // Mark the cookie as HTTP-only.
                cookie.setSecure(true); // Uncomment to make the cookie secure (HTTPS only).
                cookie.setMaxAge(2 * 60); // Set the cookie's max age (e.g., 2 minutes).
                cookie.setPath("/"); // Set the cookie's path.
                cookie.setAttribute("SameSite", NONE.name()); // Set the SameSite attribute
                // to NONE.
                response.addCookie(cookie); // Add the cookie to the response.
            }

            case REFRESH -> {
                var refreshToken = generateTokenForUser(user, Token::getRefresh); // Create a refresh token.
                var cookie = new Cookie(type.getValue(), refreshToken); // Create a new cookie with the token.
                cookie.setHttpOnly(true); // Mark the cookie as HTTP-only.
                cookie.setSecure(true); // Uncomment to make the cookie secure (HTTPS only).
                cookie.setMaxAge(2 * 60 * 60); // Set the cookie's max age (e.g., 2 hours).
                cookie.setPath("/"); // Set the cookie's path.
                cookie.setAttribute("SameSite", NONE.name()); // Set the SameSite attribute to NONE.
                response.addCookie(cookie); // Add the cookie to the response.
            }
        }
    };

    // Implementation of the generateTokenForUser method from the JwtService
    // interface.
    // public String generateTokenForUser(
    // User user, Function<Token, String> tokenFunction) {
    public String generateTokenForUser(
            User user, Function<Token, String> tokenFunction) {
        var token = Token.builder()
                .access(generateToken(user, ACCESS)) // Build the access token.
                .refresh(
                        generateToken(user, REFRESH)) // Build the refresh token.
                .build(); // Create a new Token object with the generated tokens.
        // Apply the provided token function to return the desired token (access or
        // refresh).
        return tokenFunction.apply(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String userIDFromToken = extractSubjectFromToken(token);
        User user = userService.getUserByEmail(userDetails.getUsername());
        String userId = user.getUserId();
        return userIDFromToken.equals(userId) && !isTokenExpired(token);
        // return userIDFromToken.equals(((UserEntity) userDetails).getUserId()) &&
        // !isTokenExpired(token);
    }

    public void setTokenCookieInResponse(HttpServletResponse response, User user, TokenType type) {
        System.out.println("User in JwtConfiguration ============================== " + user);
        tokenCookieSetter.accept(response, user, type); // Add the cookie using the TriConsumer.
    }

    // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    // Function to extract a specific cookie (e.g., token) from the HTTP request.
    public Optional<String> getTokenFromRequestCookie(
            HttpServletRequest request,
            String cookieName) {
        if (request.getCookies() != null) {
            return stream(request.getCookies()).filter(cookie -> Objects.equals(cookieName, cookie.getName()))
                    .map(Cookie::getValue).findAny();

        }
        return Optional.empty();
    }

    // Function to extract the authorities from the JWT token and convert them into
    // a list of GrantedAuthority objects.
    public Function<String, List<GrantedAuthority>> getAuthoritiesFromToken = token -> commaSeparatedStringToAuthorityList(
            new StringJoiner(AUTHORITY_DELIMITER)
                    // Get the authorities claim.
                    .add(parseTokenClaims(token).get(AUTHORITIES, String.class))
                    // Add the role claim.
                    .add(ROLE_PREFIX + parseTokenClaims(token).get(ROLE, String.class))
                    .toString()); // Convert to a comma-separated string.

    public <T> T extractTokenData(String token, Function<TokenData, T> toekFunction) {
        return toekFunction.apply(TokenData.builder()
                .valid(Objects.equals(userService.getUserByUserId(extractSubjectFromToken(token)).getUserId(),
                        // Validate the user ID matches the token subject.
                        parseTokenClaims(token).getSubject()))
                .authorities(getAuthoritiesFromToken.apply(token)) // Extract the authorities from the token.
                .claims(parseTokenClaims(token)) // Extract all claims from the token.
                // Fetch the user object using the token subject.
                .user(userService.getUserByUserId(extractSubjectFromToken(token)))
                .build()); // Build the TokenData object.
    }

    public void removeTokenCookies(HttpServletResponse response) {
        // Remove the ACCESS token cookie
        Cookie accessTokenCookie = new Cookie(TokenType.ACCESS.getValue(), null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(true);
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setAttribute("SameSite", "None");
        response.addCookie(accessTokenCookie);

        // Remove the REFRESH token cookie
        Cookie refreshTokenCookie = new Cookie(TokenType.REFRESH.getValue(), null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setAttribute("SameSite", "None");
        response.addCookie(refreshTokenCookie);
    }

}
