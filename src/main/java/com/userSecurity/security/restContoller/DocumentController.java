package com.userSecurity.security.restContoller;

import java.net.URI;
import java.util.Map;
import java.util.List;
import java.io.IOException;
import java.nio.file.Files;
import lombok.RequiredArgsConstructor;
import com.userSecurity.security.dto.User;
import org.springframework.http.MediaType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletRequest;
import com.userSecurity.security.domain.Response;
import static org.springframework.http.HttpStatus.OK;
import org.springframework.web.multipart.MultipartFile;
import com.userSecurity.security.service.DocumentService;
import com.userSecurity.security.service.UserService;
import static org.springframework.http.HttpStatus.CREATED;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.userSecurity.security.dtorequest.UpdateDocRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import static com.userSecurity.security.utils.RequestUtils.getResponse;
import static java.util.Collections.emptyMap;
// import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;

@RestController
@RequiredArgsConstructor
@RequestMapping("/documents")
public class DocumentController {
        private final DocumentService documentService;
        private final UserService userService;

        @PostMapping("/upload-documents")
        // @PreAuthorize("hasAnyAuthority('document:create') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> uploadDocument(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestParam("files") List<MultipartFile> documents, HttpServletRequest request) {

                User user = userService.getUserByEmail(userDetails.getUsername());

                var newDocuments = documentService.saveDocuments(user.getUserId(), documents);
                return ResponseEntity.created(URI.create(""))
                                .body(getResponse(request, Map.of("documents", newDocuments),
                                                "Documnet(s) uploaded succesfully",
                                                CREATED));
        }

        @GetMapping
        // @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> getDocuments(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestParam(value = "page", defaultValue = "0") int page,
                        @RequestParam(value = "size", defaultValue = "5") int size,
                        HttpServletRequest request) {

                var documents = documentService.getDocuments(page, size);
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("documents", documents),
                                                "Documnet(s) fetched succesfully",
                                                OK));
        }

        @GetMapping("/search")
        // @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> searchDocument(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestParam(value = "page", defaultValue = "0") int page,
                        @RequestParam(value = "size", defaultValue = "5") int size,
                        @RequestParam(value = "name", defaultValue = "") String name,

                        HttpServletRequest request) {

                var documents = documentService.getDocuments(page, size, name);
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("document", documents),
                                                "Documnet(s) fetched succesfully",
                                                OK));
        }

        @GetMapping("/find-document/{documentId}")
        // @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> getDocument(@AuthenticationPrincipal UserDetails userDetails,
                        @PathVariable("documentId") String documentId,

                        HttpServletRequest request) {

                var document = documentService.getDocumentByDocumentId(documentId);
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("document", document),
                                                "Documnet fetched succesfully",
                                                OK));
        }

        @PatchMapping("/update-document")
        // @PreAuthorize("hasAnyAuthority('document:update') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> updateDocument(@AuthenticationPrincipal UserDetails userDetails,
                        @RequestBody UpdateDocRequest document,
                        HttpServletRequest request) {

                var updatedDocument = documentService.updateDocument(document.getDocumentId(), document.getName(),
                                document.getDescription());
                return ResponseEntity.ok()
                                .body(getResponse(request, Map.of("document", updatedDocument),
                                                "Documnet updated succesfully",
                                                OK));
        }

        @DeleteMapping("/delete/{documentId}")
        // @PreAuthorize("hasAnyAuthority('document:delete') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<Response> deleteDocument(@AuthenticationPrincipal UserDetails userDetails,
                        @PathVariable("documentId") String documentId, HttpServletRequest request) {

                documentService.deleteDocument(documentId);

                return ResponseEntity.ok()
                                .body(getResponse(request, emptyMap(), "Docmuent has been deleted succesfully", OK));
        }

        @GetMapping("/download/{documentName}")
        // @PreAuthorize("hasAnyAuthority('document:read') or hasAnyRole('ADMIN',
        // 'SUPER_ADMIN')")
        public ResponseEntity<org.springframework.core.io.Resource> downloadDocument(
                        @AuthenticationPrincipal UserDetails userDetails,
                        // @AuthenticationPrincipal is used to access the currently authenticated user.
                        // The User object here represents the authenticated user making the request.
                        @PathVariable("documentName") String documentName) throws IOException {
                // @PathVariable binds the {documentName} from the URL to the method parameter.
                // The method throws IOException, which needs to be handled if the file cannot
                // be accessed.
                var resource = documentService.getResource(documentName);
                // The documentService.getResource(documentName) call retrieves the resource
                // (file) based on the documentName.
                // The resource is typically a file that is being requested for download.
                var httpHeaders = new HttpHeaders();
                // HttpHeaders is an object to hold HTTP headers. These headers can contain
                // metadata about the response.
                httpHeaders.add("File-Name", documentName);
                // Adds a custom header "File-Name" to the response, containing the original
                // name of the document being downloaded.
                httpHeaders.add(HttpHeaders.CONTENT_DISPOSITION,
                                String.format("attachment; File-Name=%s", resource.getFilename()));
                // Adds a Content-Disposition header to indicate that the response content
                // should be treated as an attachment.
                // This tells the browser to download the file rather than display it.
                // The file name for the attachment is set to the name of the resource (file)
                // being downloaded.
                return ResponseEntity.ok()

                                // Returns an HTTP 200 OK status in the response.
                                .contentType(MediaType
                                                .parseMediaType(Files.probeContentType(resource.getFile().toPath())))
                                // Sets the Content-Type header of the response based on the actual content type
                                // of the file.
                                // Files.probeContentType(resource.getFile().toPath()) is used to detect the
                                // MIME type of the file.
                                .headers(httpHeaders)
                                // Attaches the headers (including the custom "File-Name" and
                                // "Content-Disposition") to the response.
                                .body(resource);
                // Sets the body of the response to the resource, which is the file being
                // downloaded.
        }

}
