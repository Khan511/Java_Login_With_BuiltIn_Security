package com.userSecurity.security.repository;

import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;
import com.userSecurity.security.dto.api.IDocuments;
import org.springframework.data.jpa.repository.Query;
import com.userSecurity.security.entity.DocumentEntity;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import static com.userSecurity.security.constant.Constant.SELECT_DOCUMENTS_QUERY;
import static com.userSecurity.security.constant.Constant.SELECT_DOCUMENT_QUERY;
import static com.userSecurity.security.constant.Constant.SELECT_DOCUMENTS_BY_NAME_QUERY;

@Repository
public interface DocumentRepository extends JpaRepository<DocumentEntity, Long> {

    @Query(countQuery = "SELECT COUNT(*) FROM documents", value = SELECT_DOCUMENTS_QUERY, nativeQuery = true)
    Page<IDocuments> findDocuments(Pageable pageable);

    @Query(countQuery = "SELECT COUNT(*) FROM documents WHERE name ~* :documentName", value = SELECT_DOCUMENTS_BY_NAME_QUERY, nativeQuery = true)
    Page<IDocuments> findDocumentsByName(@Param("documentName") String name, Pageable pageable);

    @Query(value = SELECT_DOCUMENT_QUERY, nativeQuery = true)
    Optional<IDocuments> findDocumentByDocumentId(String documentId);

    Optional<DocumentEntity> findDocumentEntityByDocumentId(String documentId);
}
