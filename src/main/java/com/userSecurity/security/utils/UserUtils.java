package com.userSecurity.security.utils;

import java.util.UUID;
import java.time.LocalDateTime;
import java.util.function.Supplier;
import java.util.function.BiFunction;
import dev.samstevens.totp.qr.QrData;
import com.userSecurity.security.dto.User;
import org.springframework.beans.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import com.userSecurity.security.entity.RoleEntity;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.exception.ApiException;
import com.userSecurity.security.entity.CredentialEntity;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import static dev.samstevens.totp.util.Utils.getDataUriForImage;
import static com.userSecurity.security.constant.Constant.NINETY_DAYS;
import static com.userSecurity.security.constant.Constant.GET_ARRAYS_LLC;

public class UserUtils {
    public static UserEntity createUserEntity(String firstName, String lastName, String email, RoleEntity role) {

        return UserEntity.builder()
                .userId(UUID.randomUUID().toString())
                .firstName(firstName)
                .lastName(lastName)
                .email(email)
                .lastLogin(LocalDateTime.now())
                .accountNonExpired(true)
                .accountNonLocked(true)
                .mfa(false)
                .enabled(false)
                .loginAttempts(0)
                .qrCodeSecret(StringUtils.EMPTY)
                .phone(StringUtils.EMPTY)
                .bio(StringUtils.EMPTY)
                .imageUri(
                        "https://reputationtoday.in/wp-content/uploads/2019/11/110-1102775_download-empty-profile-hd-png-download.jpg")
                .role(role)
                .build();
    }

    // Converts a UserEntity object into a User object and sets additional
    // properties from RoleEntity and CredentialEntity
    public static User fromUserEntity(UserEntity userEntity, RoleEntity role,
            CredentialEntity credentialEntity) {
        // Create a new User object which will be populated with data from userEntity
        // and other entities
        User user = new User();
        // Copies all properties from userEntity to the newly created user object.
        // This will automatically copy matching fields between the two objects.
        BeanUtils.copyProperties(userEntity, user);
        user.setLastLogin(userEntity.getLastLogin().toString());

        // Set whether the user's credentials are non-expired by calling
        // isCredentialsNonExpired method,
        // which checks if the user's credentials are still valid based on a time
        // period.
        user.setCredentialsNonExpired(isCredentialsNonExpired(credentialEntity));
        user.setCreatedAt(userEntity.getCreatedAt().toString());
        user.setUpdatedAt(userEntity.getUpdatedAt().toString());
        // Set the role name in the user object, which comes from the RoleEntity.
        user.setRole(role.getName());
        // Set the authorities (permissions) for the user based on the RoleEntity.
        // This assumes that role.getAuthorities().getValue() returns a collection or
        // string of authorities.
        user.setAuthroteies(role.getAuthorities().getValue());
        // Return the fully populated User object.
        return user;
    }

    // Checks if the user's credentials have expired based on the last updated date.
    // This method compares the last update date of the credentials to the current
    // time and checks if 90 days have passed.
    public static boolean isCredentialsNonExpired(CredentialEntity credentialEntity) {
        // Adds 90 days to the last updated date of the credentials and checks if this
        // date is still in the future.
        // If the date is in the future, the credentials are considered non-expired, and
        // the method returns true.
        // Otherwise, it returns false, indicating the credentials have expired.
        return credentialEntity.getUpdatedAt().plusDays(NINETY_DAYS).isAfter(LocalDateTime.now());
    }

    public static BiFunction<String, String, QrData> qrDataFunction = (email, qrCodeSecret) -> new QrData.Builder()
            .issuer(GET_ARRAYS_LLC)
            .label(email)
            .secret(qrCodeSecret)
            .algorithm(HashingAlgorithm.SHA1)
            .digits(6)
            .period(30)
            .build();

    public static BiFunction<String, String, String> qrCodeImageUri = (email, qrCodeSecret) -> {

        var data = qrDataFunction.apply(email, qrCodeSecret);
        var generator = new ZxingPngQrGenerator();
        byte[] imageData;

        try {
            imageData = generator.generate(data);
        } catch (Exception exception) {
            throw new ApiException("Uable to create QR code URI");
        }
        return getDataUriForImage(imageData, generator.getImageMimeType());
    };
    public static Supplier<String> qrCodeSecret = () -> new DefaultSecretGenerator().generate();
}
