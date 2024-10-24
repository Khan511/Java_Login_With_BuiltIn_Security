package com.userSecurity.security.restContoller;

import java.net.URI;
import java.util.Map;
import java.nio.file.Files;
import java.io.IOException;
import java.nio.file.Paths;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import com.userSecurity.security.dto.User;
import static java.util.Collections.emptyMap;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletResponse;
import com.userSecurity.security.domain.Response;
import com.userSecurity.security.service.UserService;
import static org.springframework.http.HttpStatus.OK;
import com.userSecurity.security.enumeration.TokenType;
import com.userSecurity.security.handler.ApiLogoutHandler;
import com.userSecurity.security.security.JwtConfiguration;
import org.springframework.web.multipart.MultipartFile;
import com.userSecurity.security.dtorequest.RoleRequest;
// import org.springframework.security.core.Authentication;
import com.userSecurity.security.dtorequest.UserRequest;
import com.userSecurity.security.dtorequest.EmailRequest;
import org.springframework.web.bind.annotation.GetMapping;
import static org.springframework.http.HttpStatus.CREATED;
import com.userSecurity.security.dtorequest.QrCodeRequest;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
// import org.springframework.security.access.prepost.PreAuthorize;
import com.userSecurity.security.dtorequest.ResetPasswordRequest;
import static org.springframework.http.MediaType.IMAGE_PNG_VALUE;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;
import com.userSecurity.security.dtorequest.UpdateDatePasswordRequest;
import static com.userSecurity.security.utils.RequestUtils.getResponse;
import static com.userSecurity.security.constant.Constant.PHOTO_DIRECTORY;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;

@Slf4j
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
        private final UserService userService;
        // private final JwtService jwtService;
        private final JwtConfiguration jwtService;
        // private final UserDetailsService userDetailsService;
        private final ApiLogoutHandler apiLogoutHandler;

        @PostMapping("/register")
        public ResponseEntity<Response> saveUser(@RequestBody @Valid UserRequest user, HttpServletRequest request) {
                userService.createUser(user.getFirstName(), user.getLastName(), user.getEmail(), user.getPassword());

                return ResponseEntity.created(URI.create(""))
                                .body(getResponse(request, emptyMap(),
                                                "Account created. Check your email to enable your account",
                                                CREATED));
        }

        @GetMapping("/verify/account")
        public ResponseEntity<Response> verifyAccount(@RequestParam("key") String key, HttpServletRequest request)
                        throws InterruptedException {

                TimeUnit.SECONDS.sleep(3);
                userService.verifyAccountKey(key);
                return ResponseEntity.ok().body(getResponse(request, emptyMap(), "Account Verified", OK));
        }

        @GetMapping("/profile")
        // @PreAuthorize("hasAnyAuthority('user:read') or
        // hasAnyRole('USER','ADMIN','USER_ADMIN')")
        public ResponseEntity<Response> profile(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {

                var getUser = userService.getUserByEmail(userDetails.getUsername());

                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("user", getUser), "Prifile retrieved", OK));

        }

        @PatchMapping("/update")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> update(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestBody UserRequest userRequest,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                var user = userService.updateUser(getUser.getUserId(), userRequest.getFirstName(),
                                userRequest.getLastName(), userRequest.getEmail(), userRequest.getPhone(),
                                userRequest.getBio());
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("user", user), "User prifile updated successfully",
                                                OK));
        }

        @PatchMapping("/updaterole")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> updateRole(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestBody RoleRequest roleRequest,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                userService.updateRole(getUser.getUserId(), roleRequest.getRole());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Role updated successfully",
                                                OK));
        }

        @PatchMapping("/toggle-account-expired")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> toggleAccountExpired(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                userService.toggleAccountExpired(getUser.getUserId());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Account updated successfully",
                                                OK));
        }

        @PatchMapping("/toggle-account-locked")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> toggleAccountLocked(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                userService.toggleAccountLocked(getUser.getUserId());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Account updated successfully",
                                                OK));
        }

        @PatchMapping("/toggle-account-enabled")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> toggleAccountEnabled(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                userService.toggleAccountEnabled(getUser.getUserId());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Account updated successfully",
                                                OK));
        }

        @PatchMapping("/toggle-credential-expired")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> toggleCredentialExpired(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                userService.toggleCredentialExpired(getUser.getUserId());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Account updated successfully",
                                                OK));
        }

        @PatchMapping("/mfa/setup")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('USER', 'ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> setupMfa(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                var user = userService.setupMfa(getUser.getId());
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("user", user), "MFA set up successfully", OK));
        }

        @PatchMapping("/mfa/cancel")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> cancelMfa(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                var user = userService.cancelMfa(getUser.getId());
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("user", user), "MFA canceled successfully", OK));
        }

        @PostMapping("/verify/qrcode")
        public ResponseEntity<Response> verfyQrCode(@RequestBody QrCodeRequest qrCodeRequest,
                        HttpServletRequest request,
                        HttpServletResponse response) {
                System.out.println("============================>  " + qrCodeRequest);
                var user = userService.verifyQrCode(qrCodeRequest.getUserId(), qrCodeRequest.getQrCode());
                System.out.println("============================>  " + user);
                jwtService.setTokenCookieInResponse(response, user, TokenType.ACCESS);
                jwtService.setTokenCookieInResponse(response, user, TokenType.REFRESH);

                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("user", user), "QR code verified", OK));
        }

        // START- Reset password when user is logged in.
        @PatchMapping("/update-password")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> updatePassword(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestBody UpdateDatePasswordRequest paswordRequest,
                        HttpServletRequest request) {
                var getUser = userService.getUserByEmail(userDetails.getUsername());
                userService.updatePassword(getUser.getUserId(), paswordRequest.getPassword(),
                                paswordRequest.getNewPassword(), paswordRequest.getConfirmNewPassword());
                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Password updated successfully",
                                                OK));
        }
        // END- Reset password when user is logged in.

        // START-Reset password when not logged in
        @PostMapping("/resetpassword-link")
        public ResponseEntity<Response> resetPassword(@RequestBody @Valid EmailRequest emailRequest,
                        HttpServletRequest request) {
                userService.resetPassword(emailRequest.getEmail());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "We sent you an email to reset your password",
                                                OK));
        }

        @GetMapping("/verify/password")
        public ResponseEntity<Response> verifyPassword(@RequestParam("key") String key, HttpServletRequest request) {
                var user = userService.verifyPassword(key);

                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("user", user), "Enter new password",
                                                OK));
        }

        @PostMapping("/resetpassword/reset")
        public ResponseEntity<Response> doResetPassword(@RequestBody @Valid ResetPasswordRequest resetPasswordRequest,
                        HttpServletRequest request) {
                userService.updatePassword(resetPasswordRequest.getUserId(), resetPasswordRequest.getNewPassword(),
                                resetPasswordRequest.getConfirmNewPassword());

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Password reset successfully",
                                                OK));
        }
        // END-Reset password when not logged in

        // the follwoing method is not impelmented
        @GetMapping("/list")
        public ResponseEntity<Response> getUsers(@AuthenticationPrincipal UserDetails userDetails,
                        HttpServletRequest request) {
                return ResponseEntity.ok().body(
                                getResponse(request, Map.of("users", userService.getUsers()), "Users retrieved", OK));
        }
        // the above method is not impelmented

        @PatchMapping("/photo")
        // @PreAuthorize("hasAnyAuthority('user:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> uploadPhoto(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestParam("file") MultipartFile file,
                        HttpServletRequest request) {

                User user = userService.getUserByEmail(userDetails.getUsername());
                var imageUrl = userService.uploadPhoto(user.getUserId(), file);
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("imageUrl", imageUrl), "Photo updated successfully",
                                                OK));
        }

        @GetMapping(path = "/image/{fileName}", produces = { IMAGE_PNG_VALUE, IMAGE_JPEG_VALUE })
        public byte[] getPhoto(@PathVariable("fileName") String fileName) throws IOException {
                return Files.readAllBytes(Paths.get(PHOTO_DIRECTORY + fileName));
        }

        @PostMapping("/logout")
        public ResponseEntity<Response> logout(HttpServletRequest request,
                        HttpServletResponse response,
                        Authentication authentication) {
                apiLogoutHandler.logout(request, response, authentication);
                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "You've logged out successfully",
                                                OK));
        }

}
