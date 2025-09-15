package com.srinjay.secureApp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.srinjay.secureApp.model.Users;
import com.srinjay.secureApp.repo.UserRepo;

/**
 * UserService handles:
 *  - Registering new users (with password encryption)
 *  - Authenticating users with Spring Security
 *  - Generating JWT tokens for successful logins
 */
@Service
public class UserService {

    @Autowired
    private UserRepo repo;   // Repository for interacting with Users table in DB

    @Autowired
    private AuthenticationManager authManager; // Authenticates login credentials

    @Autowired
    private JWTService jwtService; // Used to generate JWT token after successful login

    // BCrypt password encoder (strength = 12)
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    /**
     * Register a new user.
     * - Encrypts password before saving (never store plain text!)
     * - Saves user details in the database
     *
     * @param user User object from request
     * @return saved User object (with encrypted password)
     */
    public Users register(Users user) {
        user.setPassword(encoder.encode(user.getPassword())); // encrypt password
        return repo.save(user); // save in DB
    }

    /**
     * Verify login credentials.
     * - Uses AuthenticationManager to authenticate username + password
     * - If successful, generate and return a JWT token
     * - If failed, return "Failure"
     *
     * @param user User object containing login credentials
     * @return JWT token (if success) or "Failure" (if invalid login)
     */
    public String verify(Users user) {
        // Attempt authentication with Spring Security
        Authentication authentication =
                authManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                user.getUsername(),
                                user.getPassword()
                        )
                );

        // If authentication is successful, return JWT token
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(user.getUsername());
        }

        // Otherwise, return failure response
        return "Failure";
    }
}
