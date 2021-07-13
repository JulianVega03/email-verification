package com.juliandev.amigoscode.registrationLoginEmailVerification.email;

public interface EmailSender{
    void send(String to, String email);
}
