package com.userSecurity.security.entity;

import lombok.Setter;
import lombok.Getter;
import lombok.Builder;
import lombok.ToString;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.persistence.Table;
import jakarta.persistence.Entity;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.userSecurity.security.enumeration.Authority;

@Getter
@Setter
@Entity
@Builder
@ToString
@Table(name = "roles")
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class RoleEntity extends Auditable {

    private String name;
    private Authority authorities;
}
