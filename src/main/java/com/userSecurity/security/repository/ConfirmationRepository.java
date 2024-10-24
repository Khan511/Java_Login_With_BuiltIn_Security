package com.userSecurity.security.repository;

import java.util.Optional;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.entity.ConfirmationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ConfirmationRepository extends JpaRepository<ConfirmationEntity, Long> {
    Optional<ConfirmationEntity> findByKey(String key);

    Optional<ConfirmationEntity> findByUserEntity(UserEntity userEntity);

}
