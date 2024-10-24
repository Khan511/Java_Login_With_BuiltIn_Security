package com.userSecurity.security.service;

import java.util.List;
import java.util.Collection;

import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;

import com.userSecurity.security.dto.Document;
import com.userSecurity.security.dto.api.IDocuments;
import org.springframework.web.multipart.MultipartFile;

public interface DocumentService {
    Page<IDocuments> getDocuments(int page, int size);

    Page<IDocuments> getDocuments(int page, int size, String name);

    Collection<Document> saveDocuments(String userId, List<MultipartFile> documents);

    IDocuments updateDocument(String documentId, String name, String description);

    void deleteDocument(String documentId);

    IDocuments getDocumentByDocumentId(String documentId);

    Resource getResource(String documentName);

}
