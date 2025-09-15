package com.srinjay.secureApp.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.srinjay.secureApp.service.JWTService;
import com.srinjay.secureApp.service.MyUserDetailsService;

import java.io.IOException;

/**
 * JwtFilter intercepts every incoming HTTP request (except those excluded in SecurityConfig).
 * It checks for a JWT token in the "Authorization" header and validates it.
 * 
 * If the token is valid, it sets the authentication details inside the Spring SecurityContext,
 * so that the request is treated as authenticated.
 */
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    // We use ApplicationContext here so that the filter can fetch beans dynamically.
    @Autowired
    private ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 1. Extract the Authorization header from the request
        // Format: "Bearer <token>"
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        // 2. If header exists and starts with "Bearer ", extract the token and username
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7); // Remove "Bearer " prefix
            username = jwtService.extractUserName(token); // Extract username (subject) from token
        }

        // 3. If username is extracted and SecurityContext has no authentication yet,
        //    then validate the token and set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            
            // Load user details from database using MyUserDetailsService
            UserDetails userDetails = context.getBean(MyUserDetailsService.class)
                                             .loadUserByUsername(username);

            // Validate the token against user details (e.g., expiration, signature, username match)
            if (jwtService.validateToken(token, userDetails)) {

                // Create an authentication object (username + authorities)
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                // Attach request-specific details (IP, session info)
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Store authentication in SecurityContext, so Spring knows this request is authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 4. Pass the request further down the filter chain
        filterChain.doFilter(request, response);
    }
}
