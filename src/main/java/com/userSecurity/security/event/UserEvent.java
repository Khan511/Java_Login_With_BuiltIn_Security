package com.userSecurity.security.event;

import lombok.Getter;
import lombok.Setter;
import java.util.Map;
import lombok.AllArgsConstructor;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.enumeration.EventType;

@Getter
@Setter
@AllArgsConstructor
public class UserEvent {
    private UserEntity user;
    private EventType type;
    private Map<?, ?> data;
}
