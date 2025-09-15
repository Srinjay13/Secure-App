package com.srinjay.secureApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * AppSecurityConfig defines the security configuration for the application.
 * 
 * Responsibilities:
 *  - Define which endpoints require authentication
 *  - Register custom filters (like JWT filter)
 *  - Configure how users are authenticated (via DB using UserDetailsService)
 *  - Set session management policy to stateless (important for JWT)
 */
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService; // Custom user details service (loads users from DB)

    @Autowired
    private JwtFilter jwtFilter; // Our custom filter that validates JWT tokens

    /**
     * Defines the security filter chain.
     * 
     * - Disables CSRF (not needed for stateless REST APIs)
     * - Permits /register and /login without authentication
     * - Requires authentication for all other endpoints
     * - Sets session policy to STATELESS (every request must include JWT)
     * - Adds JwtFilter before UsernamePasswordAuthenticationFilter so JWT is validated first
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()) // disable CSRF for APIs
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/register", "/login").permitAll() // public endpoints
                .anyRequest().authenticated() // all others need authentication
            )
            .httpBasic(Customizer.withDefaults()) // optional: allows basic auth (mainly for testing)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // no sessions
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class); // add JWT filter

        return http.build();
    }

    /**
     * Defines the authentication provider.
     * 
     * - Uses DaoAuthenticationProvider (fetches user details from DB via UserDetailsService)
     * - Uses BCrypt for password encoding/validation
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12)); // password hashing
        provider.setUserDetailsService(userDetailsService); // load users from DB
        return provider;
    }

    /**
     * Exposes AuthenticationManager as a Spring Bean.
     * 
     * This is needed so UserService (or other components) can perform authentication
     * programmatically (e.g., in login endpoint).
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
