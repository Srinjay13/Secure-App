package com.srinjay.secureApp.model;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

// UserPrincipal is a wrapper around our custom Users entity.
// It implements Spring Security's UserDetails interface so that
// Spring Security knows how to fetch username, password, and roles.
public class UserPrincipal implements UserDetails {

    private Users user; 
    // Reference to our Users entity from the database.

    // Constructor: accept Users object and store it
    public UserPrincipal(Users user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // This method defines the roles/authorities granted to the user.
        // Currently hard-coded as "USER" for every authenticated user.
        // Later, you can fetch roles dynamically from the Users entity.
        return Collections.singleton(new SimpleGrantedAuthority("USER"));
    }

    @Override
    public String getPassword() {
        // Return the encoded password stored in DB
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        // Return the username stored in DB
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        // If you want account expiration feature, handle it here.
        // true = account is valid and not expired.
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // If you want to implement account locking (like after multiple failed attempts),
        // handle it here. true = account is not locked.
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // For expiring/resetting credentials logic.
        // true = password/credentials are still valid.
        return true;
    }

    @Override
    public boolean isEnabled() {
        // For enabling/disabling user accounts.
        // true = user is active and can log in.
        return true;
    }
}
