package com.juliandev.amigoscode.registrationLoginEmailVerification.registration;

import lombok.Data;

@Data
public class RegistrationRequest {

    private final String firstName;
    private final String lastName;
    private final String email;
    private final String password;

}
