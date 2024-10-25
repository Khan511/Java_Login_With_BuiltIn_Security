package com.userSecurity.security.service.impl;

// import lombok.var;
import java.util.Map;
import java.util.List;
import java.util.UUID;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;
import java.util.function.BiFunction;
import lombok.RequiredArgsConstructor;
// import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import com.userSecurity.security.dto.User;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Service;
import dev.samstevens.totp.code.CodeGenerator;
import com.userSecurity.security.event.UserEvent;
import com.userSecurity.security.cache.CacheStore;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.entity.RoleEntity;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
// import com.userSecurity.security.service.JwtService;
import com.userSecurity.security.service.UserService;
import org.springframework.web.multipart.MultipartFile;
import com.userSecurity.security.domain.RequestContext;
// import com.userSecurity.security.domain.UserPrincipal;
import com.userSecurity.security.enumeration.Authority;
import com.userSecurity.security.enumeration.EventType;
import com.userSecurity.security.enumeration.LoginType;
// import com.userSecurity.security.enumeration.TokenType;
import com.userSecurity.security.exception.ApiException;
import static org.apache.commons.lang3.StringUtils.EMPTY;
// import static org.springframework.http.HttpStatus.resolve;
import com.userSecurity.security.entity.CredentialEntity;
import com.userSecurity.security.repository.UserRepository;
import com.userSecurity.security.repository.RoleRepository;
import com.userSecurity.security.entity.ConfirmationEntity;
import org.springframework.context.ApplicationEventPublisher;
import com.userSecurity.security.repository.CredentialRepository;
import com.userSecurity.security.repository.ConfirmationRepository;
import static com.userSecurity.security.utils.UserUtils.qrCodeSecret;
import static com.userSecurity.security.utils.UserUtils.qrCodeImageUri;
import static com.userSecurity.security.utils.UserUtils.fromUserEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
// import static com.userSecurity.security.constant.Constant.NINETY_DAYS
import static com.userSecurity.security.utils.UserUtils.createUserEntity;
import static com.userSecurity.security.constant.Constant.PHOTO_DIRECTORY;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import static com.userSecurity.security.validation.UserValidation.verifyAccountStatus;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(rollbackOn = Exception.class)
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final CredentialRepository credentialRepository;
    private final ConfirmationRepository confirmationRepository;
    private final PasswordEncoder encoder;
    // private final BCryptPasswordEncoder encoder;
    private final CacheStore<String, Integer> userCache;
    private final ApplicationEventPublisher publisher;
    // private final JwtService jwtService;

    // // @@@@@@@@@@@@@@@@@@@@@@
    // TO CREATE 2 TEMPORARY ROLES IN DATA BASE:
    // @PostConstruct
    // public void initRoles() {
    // if (!roleRepository.findByNameIgnoreCase("USER").isPresent()) {
    // RoleEntity userRole = new RoleEntity();
    // userRole.setName(Authority.USER.name());
    // userRole.setAuthorities(Authority.USER);
    // roleRepository.save(userRole);
    // }
    // if (!roleRepository.findByNameIgnoreCase("ADMIN").isPresent()) {
    // RoleEntity adminRole = new RoleEntity();
    // adminRole.setName(Authority.ADMIN.name());
    // adminRole.setAuthorities(Authority.ADMIN);
    // roleRepository.save(adminRole);
    // }
    // // Add more roles as needed
    // }
    // // @@@@@@@@@@@@@@@@@@@@@@
    @Override
    public void createUser(String firstName, String lastName, String email, String password) {
        var userEntity = userRepository.save(createNewUser(firstName, lastName, email));
        var credential = new CredentialEntity(userEntity, encoder.encode(password));
        credentialRepository.save(credential);

        var confirmationEntity = new ConfirmationEntity(userEntity);

        confirmationRepository.save(confirmationEntity);

        publisher.publishEvent(
                new UserEvent(userEntity, EventType.REGISTRATION, Map.of("key", confirmationEntity.getKey())));
    }

    @Override
    public RoleEntity getRoleName(String name) {
        var role = roleRepository.findByNameIgnoreCase(name);
        return role.orElseThrow(() -> new ApiException("Role not found"));
    }

    private UserEntity createNewUser(String firstName, String lastName, String email) {
        var role = getRoleName(Authority.USER.name());
        return createUserEntity(firstName, lastName, email, role);
    }

    @Transactional
    @Override
    public void verifyAccountKey(String key) {
        ConfirmationEntity confirmationEntity = getUserConfirmation(key);
        UserEntity userEntity = getUserEntityByEmail(confirmationEntity.getUserEntity().getEmail());
        RequestContext.setUserId(userEntity.getId());

        userEntity.setEnabled(true);
        userRepository.save(userEntity);

        // confirmationRepository.delete(confirmationEntity);
    }

    private UserEntity getUserEntityByEmail(String email) {
        var userByEmail = userRepository.findByEmailIgnoreCase(email);
        return userByEmail.orElseThrow(() -> new ApiException("User not found"));
    }

    private ConfirmationEntity getUserConfirmation(String key) {
        return confirmationRepository.findByKey(key)
                .orElseThrow(() -> new ApiException("Confirmation key not founddd"));
    }

    private ConfirmationEntity getUserConfirmation(UserEntity user) {
        return confirmationRepository.findByUserEntity(user).orElse(null);
    }

    // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @Override
    public void updateLoginAttempt(String email, LoginType loginType) {
        // Retrieve the user entity from the database using the email.
        var userEntity = getUserEntityByEmail(email);
        // Set the user ID in the current request context (likely for logging or
        // tracking purposes).
        RequestContext.setUserId(userEntity.getId());
        // Switch based on the type of login attempt (LOGIN_ATTEMPT or LOGIN_SUCCESS).
        switch (loginType) {
            case LOGIN_ATTEMPT -> { // Handle login attempt case
                // If the user is not found in the cache (i.e., it's their first attempt),
                // reset their login attempts to 0 and unlock their account.
                if (userCache.get(userEntity.getEmail()) == null) {
                    userEntity.setLoginAttempts(0); // Reset login attempts.
                    userEntity.setAccountNonLocked(true); // Unlock the account.
                }
                // Increment the user's login attempt count.
                userEntity.setLoginAttempts(userEntity.getLoginAttempts() + 1);

                // Update the cache with the new login attempt count.
                userCache.put(userEntity.getEmail(), userEntity.getLoginAttempts());

                // If the login attempts exceed 5, lock the user's account.
                if (userCache.get(userEntity.getEmail()) > 5) {
                    userEntity.setAccountNonLocked(false); // Lock the account.
                }
            }
            case LOGIN_SUCCESS -> { // Handle successful login case
                // If the login is successful, ensure the account is unlocked.
                userEntity.setAccountNonLocked(true);

                // Reset the login attempt count to 0.
                userEntity.setLoginAttempts(0);

                // Update the user's last login time to the current time.
                userEntity.setLastLogin(LocalDateTime.now());

                // Remove the user from the cache since their login was successful.
                userCache.evict(userEntity.getEmail());
            }
        }
        // Save the updated user entity back to the database.
        userRepository.save(userEntity);
    }

    @Override
    public User getUserByUserId(String userId) {
        var userEntity = userRepository.findUserByUserId(userId).orElseThrow(() -> new ApiException("User not found"));
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    @Override
    public User getUserByEmail(String email) {
        UserEntity userEntity = getUserEntityByEmail(email);
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    @Override
    public CredentialEntity getUserCredentialById(Long id) {

        var credentialById = credentialRepository.getCredentialByUserEntityId(id);
        return credentialById.orElseThrow(() -> new ApiException("Unable to find user credential"));
    }

    @Override
    public User setupMfa(Long id) {
        var userEntity = getUserEntityById(id);
        var codeSecret = qrCodeSecret.get();
        userEntity.setQrCodeImageUri(qrCodeImageUri.apply(userEntity.getEmail(), codeSecret));
        userEntity.setQrCodeSecret(codeSecret);
        userEntity.setMfa(true);
        userRepository.save(userEntity);
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    @Override
    public User cancelMfa(Long id) {
        var userEntity = getUserEntityById(id);
        userEntity.setMfa(false);
        userEntity.setQrCodeSecret(EMPTY);
        userEntity.setQrCodeImageUri(EMPTY);
        userRepository.save(userEntity);
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    private UserEntity getUserEntityById(Long id) {
        var userById = userRepository.findById(id);
        return userById.orElseThrow(() -> new ApiException("User not found"));
    }

    @Override
    public User verifyQrCode(String userId, String qrCode) {
        var userEntity = getUserEntityByUserId(userId);
        verifyCode(qrCode, userEntity.getQrCodeSecret());
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    private boolean verifyCode(String qrCode, String qrCodeSecret) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        if (codeVerifier.isValidCode(qrCodeSecret, qrCode)) {
            return true;
        } else {
            throw new ApiException("Invalid QR code. Please try again");
        }
    }

    private UserEntity getUserEntityByUserId(String userId) {
        var userByUserId = userRepository.findUserByUserId(userId);
        return userByUserId.orElseThrow(() -> new ApiException("User not found"));
    }

    @Override
    public void resetPassword(String email) {
        var user = getUserEntityByEmail(email);
        RequestContext.setUserId(user.getId());
        var confirmation = getUserConfirmation(user);
        if (confirmation != null) {
            // send existing confirmation
            publisher.publishEvent(
                    new UserEvent(user, EventType.RESETPASSWORD, Map.of("key", confirmation.getKey())));
        } else {
            var confirmationEntity = new ConfirmationEntity(user);
            RequestContext.setUserId(user.getId());
            confirmationRepository.save(confirmationEntity);
            publisher.publishEvent(
                    new UserEvent(user, EventType.RESETPASSWORD, Map.of("key", confirmationEntity.getKey())));
        }
    }

    @Override
    public User verifyPassword(String token) {
        ConfirmationEntity confirmationEntity = getUserConfirmation(token);
        if (confirmationEntity == null) {
            throw new ApiException("Unable to find token");
        }
        UserEntity userEntity = getUserEntityByEmail(confirmationEntity.getUserEntity().getEmail());
        if (userEntity == null) {
            throw new ApiException("Incorrect token");
        }
        verifyAccountStatus(userEntity);

        // confirmationRepository.delete(confirmationEntity);
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    // Public updated password
    @Override
    public void updatePassword(String userId, String newPassword, String confirmNewPassword) {
        if (!confirmNewPassword.equals(newPassword)) {
            throw new ApiException("Password don't match. Please try again.");
        }
        var user = getUserByUserId(userId);
        var credential = getUserCredentialById(user.getId());
        credential.setPassword(encoder.encode(newPassword));
        credentialRepository.save(credential);
    }

    @Override
    public User updateUser(String userId, String firstName, String lastName, String email, String phone, String bio) {

        var userEntity = getUserEntityByUserId(userId);
        userEntity.setFirstName(firstName);
        userEntity.setLastName(lastName);
        userEntity.setEmail(email);
        userEntity.setPhone(phone);
        userEntity.setBio(bio);

        userRepository.save(userEntity);
        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    @Override
    public void updateRole(String userId, String role) {

        var userEntity = getUserEntityByUserId(userId);
        userEntity.setRole(getRoleName(role));

        userRepository.save(userEntity);
    }

    @Override
    public void toggleAccountExpired(String userId) {
        var userEntity = getUserEntityByUserId(userId);
        userEntity.setAccountNonExpired(!userEntity.isAccountNonExpired());
        userRepository.save(userEntity);
    }

    @Override
    public void toggleAccountLocked(String userId) {
        var userEntity = getUserEntityByUserId(userId);

        userEntity.setAccountNonLocked(!userEntity.isAccountNonLocked());
        userRepository.save(userEntity);
    }

    @Override
    public void toggleAccountEnabled(String userId) {
        var userEntity = getUserEntityByUserId(userId);

        userEntity.setEnabled(!userEntity.isEnabled());
        userRepository.save(userEntity);

    }

    @Override
    public void toggleCredentialExpired(String userId) {
        var userEntity = getUserEntityByUserId(userId);

        var credential = getUserCredentialById(userEntity.getId());
        credential.setUpdatedAt(LocalDateTime.of(1995, 7, 12, 11, 11));

        // if
        // (credential.getUpdatedAt().plusDays(NINETY_DAYS).isAfter(LocalDateTime.now()))
        // {
        // credential.setUpdatedAt(LocalDateTime.now());
        // } else {
        // credential.setUpdatedAt(LocalDateTime.of(1995, 7, 12, 11, 11));
        // }

        credentialRepository.save(credential);
    }

    // Update password when logged in
    @Override
    public void updatePassword(String userId, String currentPassword, String newPassword, String confirmNewPassword) {
        if (!confirmNewPassword.equals(newPassword)) {
            throw new ApiException("Passwords don't match. Please try again");
        }
        var user = getUserEntityByUserId(userId);
        verifyAccountStatus(user);

        var credential = getUserCredentialById(user.getId());

        if (!encoder.matches(currentPassword, credential.getPassword())) {
            throw new ApiException("Existing password is incorrect. Please try again");
        }
        credential.setPassword(encoder.encode(newPassword));
        credentialRepository.save(credential);
    }

    @Override
    public String uploadPhoto(String userId, MultipartFile file) {
        var user = getUserEntityByUserId(userId);
        var photoUrl = photoFunction.apply(userId, file);
        user.setImageUri(photoUrl + "?timestapm=" + System.currentTimeMillis());
        userRepository.save(user);
        return photoUrl;
    }

    private final BiFunction<String, MultipartFile, String> photoFunction = (id, file) -> {

        var fileName = UUID.randomUUID().toString() + ".png";
        try {
            var fileStorageLocation = Paths.get(PHOTO_DIRECTORY).toAbsolutePath()
                    .normalize();
            if (!Files.exists(fileStorageLocation)) {
                Files.createDirectories(fileStorageLocation);
            }

            // Delete all exixting files in the directory before saving new one
            Files.list(fileStorageLocation).filter(currentFile -> Files.isRegularFile(currentFile))
                    .forEach(existingFile -> {
                        try {
                            Files.delete(existingFile);
                        } catch (Exception e) {
                            throw new ApiException("Unable to delte existing file: " + existingFile + e);
                        }
                    });

            Files.copy(file.getInputStream(), fileStorageLocation.resolve(fileName));

            return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/image/" + fileName).toUriString();
        } catch (Exception e) {
            throw new ApiException("unable to save image");
        }

    };

    @Override
    public User getUserById(Long id) {
        UserEntity userEntity = userRepository.findById(id).orElseThrow(() -> new ApiException("User not found"));

        return fromUserEntity(userEntity, userEntity.getRole(), getUserCredentialById(userEntity.getId()));
    }

    @Override
    public List<User> getUsers() {
        return null;
    }

    // @Override
    // public UserPrincipal getUserPrincipalByEmail(String email) {
    // // TODO Auto-generated method stub
    // throw new UnsupportedOperationException("Unimplemented method
    // 'getUserPrincipalByEmail'");
    // }

}