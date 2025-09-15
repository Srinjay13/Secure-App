package com.srinjay.secureApp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.srinjay.secureApp.model.Users;
import com.srinjay.secureApp.service.UserService;

@RestController
public class UserController {
	
	@Autowired
	private UserService service;
	
	@PostMapping("/register")
	public Users register(@RequestBody Users user) {
		return service.register(user);
	}
	
	@PostMapping("/login")
	public String login(@RequestBody Users user) {
		return service.verify(user);
	}
	
	/*
	 * 
This is the full flow of your authentication system. Let’s walk step by step in easy terms from controller → service → security → JWT filter → validation for every request.

1. User Registration Flow (/register)

Controller (UserController.register)

Accepts a Users object from the request body (e.g., { "username": "john", "password": "1234" }).

Calls UserService.register(user).

Service (UserService.register)

Encrypts the password using BCryptPasswordEncoder.

Saves the user in the database via UserRepo.save(user).

✅ At this point, the user is created in DB with an encrypted password.

2. Login Flow (/login)

Controller (UserController.login)

Accepts a Users object with username + password.

Calls UserService.verify(user).

Service (UserService.verify)

Uses AuthenticationManager to authenticate username + password.

Behind the scenes, Spring Security →

Calls your MyUserDetailsService.loadUserByUsername(username) to fetch the user from DB.

Wraps it in UserPrincipal (which Spring Security understands).

Compares the raw password (from request) with encoded password (in DB) using BCrypt.

If authentication succeeds → calls JWTService.generateToken(username) to generate a JWT token.

Returns this token to the client (Postman / frontend).

✅ Now client has a JWT token (like an ID card).

3. Using JWT for Other Requests

Now when the client wants to access another protected API (say /profile),
it must send the token in the Authorization header:

Authorization: Bearer <JWT_TOKEN>

4. JWT Validation Flow (via JwtFilter)

Every incoming request passes through JwtFilter (because we added it in AppSecurityConfig).

Steps inside JwtFilter:

Extracts the Authorization header.

If it starts with "Bearer ", it takes the token.

Calls jwtService.extractUserName(token) to get the username.

If username exists and no authentication yet →

Calls MyUserDetailsService.loadUserByUsername(username) to fetch user details from DB.

Calls jwtService.validateToken(token, userDetails) to check if token is valid (username matches + not expired).

If valid → creates an Authentication object and sets it in SecurityContextHolder.

Now the request is authenticated and allowed to hit the controller.

5. Protected API Access

In your AppSecurityConfig you defined:

.authorizeHttpRequests(auth -> auth
    .requestMatchers("/register", "/login").permitAll()
    .anyRequest().authenticated()
)


/register and /login → no authentication needed.

All other endpoints → require JWT authentication.

Example: If you had a @GetMapping("/hello"), you’d need to pass a valid JWT. Otherwise Spring Security will block it.

🔑 Full Simplified Flow

Register → save user in DB (password encrypted).

Login → validate credentials → return JWT token.

Future requests → send Authorization: Bearer <token> header.

JwtFilter → validates token → sets authentication.

Controller → runs only if request is authenticated.
*/
	 
}
