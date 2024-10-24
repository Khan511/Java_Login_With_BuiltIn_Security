package com.userSecurity.security.entity;

import lombok.Getter;
import lombok.Setter;
import lombok.Builder;
import lombok.ToString;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.persistence.Table;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ConstraintMode;
import com.fasterxml.jackson.annotation.JsonInclude;

@Getter
@Setter
@Entity
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "documents")
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public class DocumentEntity extends Auditable {
    @Column(updatable = false, unique = true, nullable = false)
    private String documentId;
    private String name;
    private String description;
    private String uri;
    private long size;
    private String formattedSize;
    private String icon;
    private String extension;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "id", foreignKey = @ForeignKey(name = "fk_documents_owner", foreignKeyDefinition = "foreign key /* FK */ (user_id) references users", value = ConstraintMode.CONSTRAINT))
    private UserEntity owner;

}
