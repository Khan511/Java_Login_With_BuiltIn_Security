package com.userSecurity.security.exception;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.validation.FieldError;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.web.context.request.WebRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import static com.userSecurity.security.utils.RequestUtils.handleErrorResponse;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

import java.nio.file.AccessDeniedException;
import java.sql.SQLIntegrityConstraintViolationException;

import java.util.stream.Collectors;

import javax.security.auth.login.CredentialExpiredException;

import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.userSecurity.security.domain.Response;

@Slf4j
@RestControllerAdvice
// This annotation allows this class to handle exceptions globally for all
// controllers.
@RequiredArgsConstructor
// This annotation automatically generates a constructor for all final fields
// (like 'request').

// This class extends ResponseEntityExceptionHandler to handle common exceptions
// and implements ErrorController to customize error handling in the
// application.
public class HandleException extends ResponseEntityExceptionHandler implements ErrorController {

        private final HttpServletRequest request;
        // This field holds the current HTTP request, which can be used to access
        // request details in exception handling.

        // Override to handle general exceptions.
        // This method is part of the custom exception handling mechanism in your
        // HandleException class, which extends ResponseEntityExceptionHandler. It
        // provides a centralized way to handle exceptions thrown during the processing
        // of an HTTP request and return meaningful error responses to the client.
        // Specifically, handleExceptionInternal is overridden to catch generic
        // exceptions and format them into a structured response
        @Override
        protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
                        HttpStatusCode statusCode, WebRequest webRequest) {

                // Log the exception message using SLF4J to help with tracking errors in the
                // logs.
                log.error(String.format("handleExceptionInternal: %s", ex.getMessage()));

                // Create a new ResponseEntity containing a structured error response using
                // 'handleErrorResponse' utility.
                // ExceptionUtils.getRootCauseMessage(ex) extracts the root cause message from
                // the exception.
                // 'request' provides additional details about the HTTP request, and
                // 'statusCode' represents the HTTP status code.
                return new ResponseEntity<>(
                                handleErrorResponse(ex.getMessage(), ExceptionUtils.getRootCauseMessage(ex), request,
                                                statusCode),
                                statusCode); // The response is returned with the provided HTTP status code.
        }

        // This method specifically handles validation errors that occur when a
        // controller's method argument (e.g., a @RequestBody object) does not pass
        // validation (for example, when using @Valid or @Validated). It's designed to
        // catch MethodArgumentNotValidException and generate a detailed response that
        // highlights the validation issues.
        // Override to handle validation errors that occur when method arguments don't
        // pass validation (e.g., @Valid).
        @Override
        protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException exception,
                        HttpHeaders headers, HttpStatusCode statusCode, WebRequest webRequest) {

                // Log the validation error message for debugging purposes.
                log.error(String.format("handleMethodArgumentNotValid: %s", exception.getMessage()));

                // Extract field validation errors from the MethodArgumentNotValidException.
                // exception.getBindingResult() provides details about validation errors.
                // Get a list of FieldError objects, each representing a failed validation on a
                // specific field.
                var fieldErrors = exception.getBindingResult().getFieldErrors();

                // Stream through the field errors and collect the default error messages into a
                // single string, joined by commas.
                // This provides a user-friendly summary of all validation issues.
                var fieldsMessage = fieldErrors.stream()
                                .map(FieldError::getDefaultMessage)
                                // Extract the default validation error message for each field.
                                .collect(Collectors.joining(", ")); // Join the messages into a single string.

                // Create a new ResponseEntity containing a structured error response, with a
                // message summarizing the validation errors.
                // ExceptionUtils.getRootCauseMessage(exception) retrieves the root cause of the
                // exception.
                // The structured error response is returned with the appropriate HTTP status
                // code.
                return new ResponseEntity<>(
                                handleErrorResponse(fieldsMessage, ExceptionUtils.getRootCauseMessage(exception),
                                                request, statusCode),
                                statusCode); // Return the response with the HTTP status code.
        }

        @ExceptionHandler(ApiException.class)
        public ResponseEntity<Response> apiException(ApiException exception) {
                log.error(String.format("ApiException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(BadCredentialsException.class)
        public ResponseEntity<Response> badCredentialsException(BadCredentialsException exception) {
                log.error(String.format("BadCredentialsException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(SQLIntegrityConstraintViolationException.class)
        public ResponseEntity<Response> sQLIntegrityConstraintViolationException(
                        SQLIntegrityConstraintViolationException exception) {
                log.error(String.format("SQLIntegrityConstraintViolationException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(UnrecognizedPropertyException.class)
        public ResponseEntity<Response> unrecognizedPropertyException(
                        UnrecognizedPropertyException exception) {
                log.error(String.format("UnrecognizedPropertyException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<Response> accessDeniedException(
                        AccessDeniedException exception) {
                log.error(String.format("AccessDeniedException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<Response> exception(
                        Exception exception) {
                log.error(String.format("Exception: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(processErrorMessage(exception),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(TransactionSystemException.class)
        public ResponseEntity<Response> transactionSystemException(
                        TransactionSystemException exception) {
                log.error(String.format("TransactionSystemException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(EmptyResultDataAccessException.class)
        public ResponseEntity<Response> emptyResultDataAccessException(
                        EmptyResultDataAccessException exception) {
                log.error(String.format("EmptyResultDataAccessException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(CredentialExpiredException.class)
        public ResponseEntity<Response> credentialExpiredException(
                        CredentialExpiredException exception) {
                log.error(String.format("CredentialExpiredException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(DisabledException.class)
        public ResponseEntity<Response> disabledException(
                        DisabledException exception) {
                log.error(String.format("DisabledException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(LockedException.class)
        public ResponseEntity<Response> lockedException(
                        LockedException exception) {
                log.error(String.format("LockedException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(exception.getMessage(),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(DuplicateKeyException.class)
        public ResponseEntity<Response> duplicateKeyException(
                        DuplicateKeyException exception) {
                log.error(String.format("DuplicateKeyException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(processErrorMessage(exception),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(DataIntegrityViolationException.class)
        public ResponseEntity<Response> dataIntegrityViolationException(
                        DataIntegrityViolationException exception) {
                log.error(String.format("DataIntegrityViolationException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(processErrorMessage(exception),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        @ExceptionHandler(DataAccessException.class)
        public ResponseEntity<Response> dataAccessException(
                        DataAccessException exception) {
                log.error(String.format("DataAccessException: %s", exception.getMessage()));
                return new ResponseEntity<>(handleErrorResponse(processErrorMessage(exception),
                                ExceptionUtils.getRootCauseMessage(exception), request, BAD_REQUEST), BAD_REQUEST);
        }

        private String processErrorMessage(Exception exception) {
                if (exception instanceof ApiException) {
                        return exception.getMessage();
                }
                if (exception.getMessage() != null) {
                        if (exception.getMessage().contains("duplicate")
                                        && exception.getMessage().contains("AccountVerifications")) {
                                return "You already verified your account";
                        }
                }
                if (exception.getMessage().contains("duplicate")
                                && exception.getMessage().contains("ResetPasswordVerifications")) {
                        return "We already sent you an email to reset your password";
                }
                if (exception.getMessage().contains("duplicate")
                                && exception.getMessage().contains("Key (email)")) {
                        return "Email already exists. User a different email and try again.";
                }
                if (exception.getMessage().contains("duplicate")) {
                        return "Duplicate entry. Please try again.";
                }
                return "An error occurred.  Please try again.";
        }
}
