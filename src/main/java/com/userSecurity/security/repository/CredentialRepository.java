package com.userSecurity.security.repository;

import java.util.Optional;
import org.springframework.stereotype.Repository;
import com.userSecurity.security.entity.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface CredentialRepository extends JpaRepository<CredentialEntity, Long> {
    Optional<CredentialEntity> getCredentialByUserEntityId(Long userId);

}
