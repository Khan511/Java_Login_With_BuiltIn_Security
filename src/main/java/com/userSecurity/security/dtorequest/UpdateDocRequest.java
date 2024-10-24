package com.userSecurity.security.dtorequest;

import lombok.Getter;
import lombok.Setter;
import jakarta.validation.constraints.NotEmpty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UpdateDocRequest {
    @NotEmpty(message = "Document ID   cannot be empty or null")
    private String documentId;
    @NotEmpty(message = "Name cannot be empty or null")
    private String name;
    @NotEmpty(message = "Dexcription cannot be empty or null")
    private String description;

}
