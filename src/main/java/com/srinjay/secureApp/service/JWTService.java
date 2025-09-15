package com.srinjay.secureApp.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * JWTService is responsible for:
 *  - Generating JWT tokens
 *  - Extracting data (claims) from tokens
 *  - Validating tokens against user details
 *
 * It ensures secure authentication by signing tokens with a secret key.
 */
@Service
public class JWTService {

    // Secret key for signing and verifying JWTs
    private String secretkey = "";

    /**
     * Constructor generates a random HmacSHA256 secret key at application startup.
     * This ensures tokens are cryptographically signed and tamper-proof.
     */
    public JWTService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk = keyGen.generateKey();
            secretkey = Base64.getEncoder().encodeToString(sk.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate a JWT token for a given username.
     *
     * @param username the username for which token is generated
     * @return signed JWT token string
     */
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .claims()                               // start adding claims
                .add(claims)                            // (custom data if needed)
                .subject(username)                      // set subject = username
                .issuedAt(new Date(System.currentTimeMillis())) // issue time
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 30)) // expiry time
                .and()
                .signWith(getKey())                     // sign with secret key
                .compact();                             // build final token
    }

    /**
     * Returns the secret key object for signing/verifying tokens.
     */
    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extract the username (subject) from a token.
     */
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract a specific claim from token using a claim resolver function.
     *
     * @param token JWT token
     * @param claimResolver lambda to extract desired claim (e.g., subject, expiration)
     * @param <T> generic return type
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    /**
     * Extract all claims (payload) from a JWT token.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())       // verify token signature with secret key
                .build()
                .parseSignedClaims(token)   // parse and return claims
                .getPayload();
    }

    /**
     * Validate a JWT token:
     *  - Check if username inside token matches UserDetails
     *  - Ensure token is not expired
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * Check if token is expired.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extract expiration date from token.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
