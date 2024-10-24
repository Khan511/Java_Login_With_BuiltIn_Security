package com.userSecurity.security.service.impl;

import java.util.List;
import java.util.UUID;
import java.util.Objects;
import java.util.ArrayList;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import jakarta.transaction.Transactional;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import com.userSecurity.security.dto.Document;
import org.springframework.data.domain.PageRequest;
import com.userSecurity.security.dto.api.IDocuments;
import com.userSecurity.security.service.UserService;
import org.springframework.web.multipart.MultipartFile;
import com.userSecurity.security.entity.DocumentEntity;
import com.userSecurity.security.entity.UserEntity;
import com.userSecurity.security.exception.ApiException;
import com.userSecurity.security.service.DocumentService;
import com.userSecurity.security.repository.UserRepository;
import static org.springframework.util.StringUtils.cleanPath;
import static org.apache.commons.io.FilenameUtils.getExtension;
import com.userSecurity.security.repository.DocumentRepository;
import static com.userSecurity.security.utils.DocumentUtils.setIcon;
import static org.apache.commons.io.FileUtils.byteCountToDisplaySize;
import static com.userSecurity.security.constant.Constant.FILE_STORAGE;
import static com.userSecurity.security.utils.DocumentUtils.getDocumentUri;
import static com.userSecurity.security.utils.DocumentUtils.fromDocumentEntity;

@Slf4j
@Service
@Transactional(rollbackOn = Exception.class)
@RequiredArgsConstructor
public class DocumentServiceImpl implements DocumentService {
    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final UserService userService;

    @Override
    public Page<IDocuments> getDocuments(int page, int size) {
        // return documentRepository.findDocuments(PageRequest.of(page, size));
        return documentRepository.findDocuments(PageRequest.of(page, size,
                Sort.by("name")));
    }

    @Override
    public Page<IDocuments> getDocuments(int page, int size, String name) {
        return documentRepository.findDocumentsByName(name, PageRequest.of(page, size,
                Sort.by("name")));
    }

    @Override
    public Collection<Document> saveDocuments(String userId, List<MultipartFile> documents) {
        List<Document> newDocuments = new ArrayList<>();
        var userEntity = userRepository.findUserByUserId(userId).get();
        var storage = Paths.get(FILE_STORAGE).toAbsolutePath().normalize();

        try {
            for (MultipartFile document : documents) {
                var fileName = cleanPath(Objects.requireNonNull(document.getOriginalFilename()));
                if ("..".contains(fileName)) {
                    throw new ApiException(String.format("Invalid file name: %s", fileName));
                }
                var documentEntity = DocumentEntity
                        .builder()
                        .documentId(UUID.randomUUID().toString())
                        .name(fileName)
                        .owner(userEntity)
                        .extension(getExtension(fileName))
                        .uri(getDocumentUri(fileName))
                        .formattedSize(byteCountToDisplaySize(document.getSize()))
                        .icon(setIcon(getExtension(fileName)))
                        .build();

                var savedDocument = documentRepository.save(documentEntity);
                // If file already exist chage the name of the new file
                Path targetLocation = storage.resolve(fileName);
                if (Files.exists(targetLocation)) {
                    String newFileName = System.currentTimeMillis() + "_" + fileName;
                    targetLocation = storage.resolve(newFileName);
                }
                Files.copy(document.getInputStream(), targetLocation);

                Document newDocument = fromDocumentEntity(savedDocument,
                        userService.getUserById(savedDocument.getCreatedBy()),
                        userService.getUserById(savedDocument.getUpdatedBy()));
                newDocuments.add(newDocument);
            }
            return newDocuments;
        } catch (Exception e) {
            throw new ApiException("Unable to save documents: " + e.getMessage());
        }
    }

    @Override
    public IDocuments updateDocument(String documentId, String name, String description) {
        try {
            DocumentEntity documentEntity = getDocumentEntity(documentId);
            var document = Paths.get(FILE_STORAGE).resolve(documentEntity.getName()).toAbsolutePath().normalize();
            Files.move(document, document.resolveSibling(name));

            documentEntity.setName(name);
            documentEntity.setDescription(description);
            documentRepository.save(documentEntity);

            return getDocumentByDocumentId(documentId);
        } catch (Exception e) {
            throw new ApiException("Unable to update documenttt");
        }
    }

    private DocumentEntity getDocumentEntity(String documentId) {
        return documentRepository.findDocumentEntityByDocumentId(documentId)
                .orElseThrow(() -> new ApiException("Document not found"));
    }

    @Override
    public void deleteDocument(String documentId) {

        var documentEntity = documentRepository.findDocumentByDocumentId(documentId)
                .orElseThrow(() -> new ApiException("Document not found with id: " + documentId));

        UserEntity userEntity = userRepository.findByEmailIgnoreCase(documentEntity.getOwner_Email()).get();

        System.out.println("=================================userEnity: " + userEntity);
        System.out.println("=================================user Role: " + userEntity.getRole().getName());
        if (!userEntity.getRole().getName().equals("ADMIN")) {
            throw new ApiException("You are not authorized to delete the document");
        }
        String fileName = documentEntity.getUri().substring(documentEntity.getUri().lastIndexOf("/") + 1);

        String decodedFileName = URLDecoder.decode(fileName, StandardCharsets.UTF_8);

        // Construct the full file path based on the known folder and the extracted file
        // name
        Path filePath = Paths.get(System.getProperty("user.home") + "/downloads/uploads/" + decodedFileName)
                .toAbsolutePath().normalize();
        try {
            if (Files.exists(filePath)) {
                // Step1. Delete the file from the file system
                Files.delete(filePath);

            } else {
                throw new ApiException(
                        "File not found on file system but proceeding to delete documetn from computer ");
            }
            // Step 2: Delete the document entity from the database
            documentRepository.deleteById(documentEntity.getId());

        } catch (IOException e) {
            throw new ApiException("Error while deleting the file storage: " + e.getMessage());
        } catch (Exception e) {
            throw new ApiException("Unable to delete the document: " + e.getMessage());
        }
    }

    @Override
    public IDocuments getDocumentByDocumentId(String documentId) {
        return documentRepository.findDocumentByDocumentId(documentId)
                .orElseThrow(() -> new ApiException("Unable to find the document"));
    }

    @Override
    public Resource getResource(String documentName) {

        try {
            var filePath = Paths.get(FILE_STORAGE).toAbsolutePath().normalize().resolve(documentName);
            if (!Files.exists(filePath)) {
                throw new ApiException("Document not found");
            }
            return new UrlResource(filePath.toUri());

        } catch (Exception e) {
            throw new ApiException("Unable to download document");
        }
    }
}
