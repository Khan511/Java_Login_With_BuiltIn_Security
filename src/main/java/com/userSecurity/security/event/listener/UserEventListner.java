package com.userSecurity.security.event.listener;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import com.userSecurity.security.event.UserEvent;
import com.userSecurity.security.service.EmailService;
import org.springframework.context.event.EventListener;

@Component
@RequiredArgsConstructor
public class UserEventListner {

    private final EmailService emailService;

    @EventListener
    public void onUserEvent(UserEvent userEvent) {
        switch (userEvent.getType()) {
            case REGISTRATION -> emailService.sendNewAccountEmail(userEvent.getUser().getFirstName(),
                    userEvent.getUser().getEmail(), (String) userEvent.getData().get("key"));

            case RESETPASSWORD -> emailService.sendPasswordResetEmail(userEvent.getUser().getFirstName(),
                    userEvent.getUser().getEmail(), (String) userEvent.getData().get("key"));

            default -> {
            }
        }
    }
}
