package com.userSecurity.security.enumeration.converter;

import java.util.stream.Stream;
import jakarta.persistence.Converter;
import jakarta.persistence.AttributeConverter;
import com.userSecurity.security.enumeration.Authority;

@Converter(autoApply = true)
public class RoleConverter implements AttributeConverter<Authority, String> {

    @Override
    public String convertToDatabaseColumn(Authority authority) {
        if (authority == null) {
            return null;
        }
        return authority.getValue();
    }

    @Override
    public Authority convertToEntityAttribute(String code) {

        if (code == null) {
            return null;
        }
        return Stream.of(Authority.values()).filter(authority -> authority.getValue().equals(code)).findFirst()
                .orElseThrow(IllegalArgumentException::new);
    }
}
