package com.userSecurity.security.service.impl;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.mail.SimpleMailMessage;
import com.userSecurity.security.service.EmailService;
import org.springframework.scheduling.annotation.Async;
import org.springframework.mail.javamail.JavaMailSender;
import com.userSecurity.security.exception.ApiException;
import org.springframework.beans.factory.annotation.Value;
import static com.userSecurity.security.utils.EmailUtils.getEmailMessage;
import static com.userSecurity.security.utils.EmailUtils.getResetPasswordMessage;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private static final String PASSWORD_RESET_REQUEST = "Reset Password Request";
    private static final String NEW_USER_ACCOUNT_VERIFICATION = "New User Account Verification";

    private final JavaMailSender sender;

    @Value("${spring.mail.verify.host}")
    private String host;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Override
    @Async
    public void sendNewAccountEmail(String name, String email, String token) {
        try {
            var message = new SimpleMailMessage();

            message.setSubject(NEW_USER_ACCOUNT_VERIFICATION);
            message.setFrom(fromEmail);
            message.setTo(email);
            message.setText(getEmailMessage(name, host, token));
            sender.send(message);
        } catch (Exception e) {
            // log.error(e.getMessage());
            log.error("Failed to send email to {}. Error: {}", email, e.getMessage());

            throw new ApiException("Unable to send email");
        }
    }

    @Override
    @Async
    public void sendPasswordResetEmail(String name, String email, String token) {
        try {
            var message = new SimpleMailMessage();

            message.setSubject(PASSWORD_RESET_REQUEST);
            message.setFrom(fromEmail);
            message.setTo(email);
            message.setText(getResetPasswordMessage(name, host, token));
            sender.send(message);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new ApiException("Unable to send email");
        }
    }
}
