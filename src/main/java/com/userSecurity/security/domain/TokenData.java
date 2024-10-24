
package com.userSecurity.security.domain;

import lombok.Setter;
import lombok.Getter;
import java.util.List;
import lombok.Builder;
import io.jsonwebtoken.Claims;
import com.userSecurity.security.dto.User;
import org.springframework.security.core.GrantedAuthority;

@Builder
@Getter
@Setter
public class TokenData {

    private User user;
    private Claims claims;
    private boolean valid;
    private List<GrantedAuthority> authorities;
}