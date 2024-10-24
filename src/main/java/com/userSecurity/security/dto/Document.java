package com.userSecurity.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.Builder;
import java.time.LocalDateTime;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Document {
    private Long id;
    private String documentId;
    private String name;
    private String description;
    private String uri;
    private long size;
    private String formattedSize;
    private String icon;
    private String extension;
    private String referenceId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String ownerName;
    private String ownerEmail;
    private String ownerPhone;
    private String ownerLastlogin;
    private String updaterName;
}
