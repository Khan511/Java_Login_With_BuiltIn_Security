package com.userSecurity.security.utils;

import java.util.Map;
import java.time.LocalDateTime;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;

import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import static java.util.Collections.emptyMap;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatusCode;
import jakarta.servlet.http.HttpServletResponse;
import com.userSecurity.security.domain.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.userSecurity.security.exception.ApiException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.LockedException;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import org.springframework.security.authentication.DisabledException;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InsufficientAuthenticationException;

public class RequestUtils {

    // A BiConsumer that writes a Response object to the HttpServletResponse's
    // output stream.
    // This is used to send JSON responses back to the client.
    private static final BiConsumer<HttpServletResponse, Response> writeResponse = (httpServletResponse, response) -> {
        try {
            // Get the output stream from the HttpServletResponse to write the response
            // data.
            var outputStream = httpServletResponse.getOutputStream();

            // Use ObjectMapper to convert the Response object into JSON and write it to the
            // output stream.
            new ObjectMapper().writeValue(outputStream, response);

            // Flush the output stream to ensure all data is sent to the client.
            outputStream.flush();
        } catch (Exception e) {

            // If an exception occurs, wrap it in a custom ApiException and rethrow it.
            throw new ApiException(e.getMessage());
        }
    };

    // A BiFunction that determines the error reason based on the exception and HTTP
    // status code.
    // This is used to provide meaningful error messages in the response.
    private static final BiFunction<Exception, HttpStatus, String> errorReason = (exception, httpStatus) -> {

        // If the status is 403 Forbidden, return a specific permission error message.
        if (httpStatus.isSameCodeAs(FORBIDDEN)) {
            return "You do not have enough permission";
        }
        // If the status is 401 Unauthorized, return a login-related error message.
        if (httpStatus.isSameCodeAs(UNAUTHORIZED)) {
            return "You are not logged in";
        }
        // For specific exceptions related to authentication or API errors, return the
        // exception's message.
        if (exception instanceof DisabledException || exception instanceof LockedException
                || exception instanceof AccountExpiredException
                || exception instanceof BadCredentialsException || exception instanceof CredentialsExpiredException

                || exception instanceof ApiException) {
            return exception.getMessage();
        }
        // If the status indicates a server error (5xx), return a generic server error
        // message.
        if (httpStatus.is5xxServerError()) {
            return "An internal server error occurreddddd";
        } else {
            // For other cases, return a general error message.
            return "An error occurred. Please try again";
        }
    };

    // Method to create a Response object based on the given request, data, message,
    // and HTTP status.
    // This is used to construct a standardized response structure for the client.
    public static Response getResponse(HttpServletRequest request, Map<?, ?> data, String message,
            HttpStatus status) {
        // Create a new Response object with the current timestamp, status code, request
        // URI, message, and data.
        return new Response(LocalDateTime.now().toString(), status.value(), request.getRequestURI(),
                HttpStatus.valueOf(status.value()), message, StringUtils.EMPTY, data);
    };

    // 1
    public static Response handleErrorResponse(String message, String exception, HttpServletRequest request,
            HttpStatusCode status) {

        return new Response(LocalDateTime.now().toString(), status.value(), request.getRequestURI(),
                HttpStatus.valueOf(status.value()), message, exception, emptyMap());
    }

    // 2
    // Method to handle error responses. It sends an appropriate error response to
    // the client based on the exception.
    public static void handleErrorResponse(HttpServletRequest request, HttpServletResponse response,
            Exception exception) {

        // If the exception is related to access denial (e.g., 403 Forbidden), create a
        // response with FORBIDDEN status.
        if (exception instanceof AccessDeniedException) {
            Response apiResponse = getErrorResponse(request, response, exception, HttpStatus.FORBIDDEN);
            // Write the error response to the HttpServletResponse using the writeResponse
            // BiConsumer.
            writeResponse.accept(response, apiResponse);

        } else if (exception instanceof InsufficientAuthenticationException) {
            var apiResponse = getErrorResponse(request, response, exception, UNAUTHORIZED);
            writeResponse.accept(response, apiResponse);

        } else if (exception instanceof MismatchedInputException) {
            var apiResponse = getErrorResponse(request, response, exception, BAD_REQUEST);
            writeResponse.accept(response, apiResponse);

        } else if (exception instanceof DisabledException || exception instanceof LockedException
                || exception instanceof BadCredentialsException || exception instanceof CredentialsExpiredException
                || exception instanceof AccountExpiredException
                || exception instanceof ApiException) {

            var apiResponse = getErrorResponse(request, response, exception, BAD_REQUEST);
            writeResponse.accept(response, apiResponse);

        } else {
            Response apiResponse = getErrorResponse(request, response, exception, INTERNAL_SERVER_ERROR);
            writeResponse.accept(response, apiResponse);
        }

    }

    // Private method to create an error Response object based on the request,
    // response, exception, and status.
    // This method is used internally to handle error scenarios.
    private static Response getErrorResponse(HttpServletRequest request, HttpServletResponse response,
            Exception exception, HttpStatus status) {
        // Set the content type of the response to JSON.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Set the HTTP status code for the response.
        response.setStatus(status.value());

        // Create and return a Response object containing error details, such as
        // timestamp, status code, URI, and error message.
        return new Response(LocalDateTime.now().toString(), status.value(), request.getRequestURI(),
                HttpStatus.valueOf(status.value()),
                // Determine the error reason using the errorReason BiFunction.
                errorReason.apply(exception, status),
                // Get the root cause message of the exception.
                ExceptionUtils.getRootCauseMessage(exception),
                // Provide an empty map for the response data, as this is an error response.
                emptyMap());
    };
}
