package com.srinjay.secureApp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.srinjay.secureApp.model.UserPrincipal;
import com.srinjay.secureApp.model.Users;
import com.srinjay.secureApp.repo.UserRepo;

@Service
// Marks this class as a Spring-managed service component.
// Spring will auto-detect it and create a bean for dependency injection.
public class MyUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepo repo; 
    // Injects the UserRepo so we can fetch user details from the database.

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // This method is called automatically by Spring Security when a user tries to log in.
        // It loads user details based on the provided username.

        Users user = repo.findByUsername(username);
        // Query the database for the user with the given username.

        if (user == null) {
            System.out.println("User Not Found");
            throw new UsernameNotFoundException(username + " not found");
            // If no user exists in DB, throw exception (mandatory for Spring Security).
        }

        // If found, wrap our custom Users entity inside UserPrincipal
        // UserPrincipal implements Spring Security's UserDetails interface
        // so that Spring Security can understand roles, username, and password.
        return new UserPrincipal(user);
    }
}
