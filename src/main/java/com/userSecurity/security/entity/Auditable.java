package com.userSecurity.security.entity;

// import lombok.var;
import lombok.Setter;
import lombok.Getter;
import jakarta.persistence.Id;
import java.time.LocalDateTime;
import jakarta.persistence.Column;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.PrePersist;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.SequenceGenerator;
import jakarta.validation.constraints.NotNull;
import com.userSecurity.security.domain.RequestContext;
import org.springframework.data.annotation.CreatedDate;
import com.userSecurity.security.exception.ApiException;
import org.springframework.util.AlternativeJdkIdGenerator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(value = { "createdAt", "updatedAt" }, allowGetters = true)
public abstract class Auditable {

    @Id
    @SequenceGenerator(name = "primary_key_seq", sequenceName = "primary_key_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "primary_key_seq")
    @Column(name = "id", updatable = false)
    private Long id;
    private String referenceId = new AlternativeJdkIdGenerator().generateId().toString();
    @NotNull
    private Long createdBy;
    @NotNull
    private Long updatedBy;
    @NotNull
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    @CreatedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    public void beforePersist() {
        // var userId = 0L;
        var userId = RequestContext.getUserId();
        if (userId == null) {
            throw new ApiException("Cannot persist entity without user ID in Request Context for this thread");
        }
        setCreatedAt(LocalDateTime.now());
        setCreatedBy(userId);
        setUpdatedBy(userId);
        setUpdatedAt(LocalDateTime.now());
    }

    @PreUpdate
    public void beforeUpdate() {
        // var userId = 0L;
        var userId = RequestContext.getUserId();
        if (userId == null) {
            throw new ApiException("Cannot update entity without user ID in Request Context for this thread");
        }
        setUpdatedAt(LocalDateTime.now());
        setUpdatedBy(userId);
    }

}
