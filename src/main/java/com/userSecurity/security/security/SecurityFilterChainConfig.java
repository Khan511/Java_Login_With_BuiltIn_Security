package com.userSecurity.security.security;

import java.util.List;
import java.util.Arrays;
import org.springframework.context.annotation.Bean;
import static org.springframework.http.HttpMethod.GET;
import org.springframework.web.cors.CorsConfiguration;
import static org.springframework.http.HttpMethod.PUT;
import static com.google.common.net.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpMethod.POST;
import static com.google.common.net.HttpHeaders.ORIGIN;
import static org.springframework.http.HttpMethod.PATCH;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.OPTIONS;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.web.cors.CorsConfigurationSource;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static com.google.common.net.HttpHeaders.X_REQUESTED_WITH;
import static com.userSecurity.security.constant.Constant.FILE_NAME;
import static com.userSecurity.security.constant.Constant.PUBLIC_URLS;
import static com.userSecurity.security.constant.Constant.BASE_PATH;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.userSecurity.security.handler.ApiAccessDeniedHandler;
import com.userSecurity.security.handler.ApiAthenticationEntryPoint;

import lombok.RequiredArgsConstructor;
import static com.google.common.net.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static com.google.common.net.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD;
import static com.google.common.net.HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import static com.google.common.net.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
@EnableSpringDataWebSupport
public class SecurityFilterChainConfig {

        private final ApiAccessDeniedHandler apiAccessDeniedHandler;
        private final ApiAthenticationEntryPoint apiAthenticationEntryPoint;
        private final CustomSecurityConfigurer customSecurityConfigurer;
        //

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

                httpSecurity.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .formLogin(AbstractHttpConfigurer::disable)// Disable default form login

                                .sessionManagement((session -> session
                                                .sessionCreationPolicy(
                                                                SessionCreationPolicy.STATELESS)))
                                .exceptionHandling(exception -> exception
                                                .accessDeniedHandler(apiAccessDeniedHandler)
                                                .authenticationEntryPoint(apiAthenticationEntryPoint)

                                )

                                .authorizeHttpRequests(requests -> requests
                                                .requestMatchers(PUBLIC_URLS)
                                                .permitAll()
                                                .requestMatchers(HttpMethod.OPTIONS)
                                                .permitAll()
                                                .requestMatchers("/api/auth/**").permitAll()
                                                .requestMatchers("/h2-console/**").permitAll()
                                                .requestMatchers("/user/login").permitAll()
                                                .requestMatchers("/auth/logout").permitAll()

                                                .requestMatchers(HttpMethod.DELETE, "/user/delete/**")
                                                .hasAnyAuthority("user:delete")
                                                .requestMatchers(HttpMethod.DELETE, "/document/delete")
                                                .hasAnyRole("ADMIN", "SUPER_ADMIN")
                                                .requestMatchers(HttpMethod.GET, "/profile")
                                                .access(new WebExpressionAuthorizationManager(
                                                                "hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN') or hasAnyAuthority('user:update')"))

                                                .anyRequest()
                                                .authenticated())
                                .headers(headers -> headers
                                                .frameOptions(frameOptions -> frameOptions.sameOrigin()) // Allow frames
                                // from the
                                // same origin
                                )
                                .with(customSecurityConfigurer, Customizer.withDefaults());

                return httpSecurity.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                var corsConfiguration = new CorsConfiguration();
                corsConfiguration.setAllowCredentials(true);
                corsConfiguration
                                .setAllowedOrigins(List.of("http://securedoc.com", "http://localhost:4200",
                                                "http://localhost:5173", "http://localhost:5173/documents",
                                                "http://localhost:3000"));
                corsConfiguration.setAllowedHeaders(
                                Arrays.asList(ORIGIN, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, ACCEPT,
                                                AUTHORIZATION, X_REQUESTED_WITH, ACCESS_CONTROL_REQUEST_METHOD,
                                                ACCESS_CONTROL_REQUEST_HEADERS,
                                                ACCESS_CONTROL_ALLOW_CREDENTIALS, FILE_NAME));

                corsConfiguration.setExposedHeaders(
                                Arrays.asList(ORIGIN, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, ACCEPT,
                                                AUTHORIZATION, X_REQUESTED_WITH, ACCESS_CONTROL_REQUEST_METHOD,
                                                ACCESS_CONTROL_REQUEST_HEADERS,
                                                ACCESS_CONTROL_ALLOW_CREDENTIALS, FILE_NAME));

                corsConfiguration.setAllowedMethods(
                                Arrays.asList(GET.name(), POST.name(), PUT.name(), PATCH.name(),
                                                DELETE.name(),
                                                OPTIONS.name()));

                corsConfiguration.setMaxAge(3600L);
                var source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration(BASE_PATH, corsConfiguration);
                return source;
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
                        throws Exception {
                return authenticationConfiguration.getAuthenticationManager();
        }

}
