package com.userSecurity.security.repository;

import java.util.Optional;
import org.springframework.stereotype.Repository;
import com.userSecurity.security.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByEmailIgnoreCase(String email);

    Optional<UserEntity> findUserByUserId(String userId);

    // Optional<UserEntity> findUserByUserName(String userName);
}
