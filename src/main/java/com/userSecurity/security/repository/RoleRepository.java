package com.userSecurity.security.repository;

import java.util.Optional;
import org.springframework.stereotype.Repository;
import com.userSecurity.security.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    Optional<RoleEntity> findByNameIgnoreCase(String name);

}
