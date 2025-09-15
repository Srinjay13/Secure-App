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

@Configuration
//The @Configuration annotation in Spring Boot indicates that a class serves as a source of bean definitions for the Spring IoC (Inversion of Control) container. It is a class-level annotation, meaning it is applied to an entire class, not to individual methods or fields.
@EnableWebSecurity
//The @EnableWebSecurity annotation in Spring Boot enables and configures Spring Security for a web application. When applied to a @Configuration class, it triggers the necessary setup to secure your application's web endpoints.
public class AppSecurityConfig {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http.csrf(customizer -> customizer.disable());
		//This is used to disable the CSRF Token for our page (request.requestMatchers("register","login").permitAll() this means that for this two urls, it will not require authentication)
//		http.authorizeHttpRequests(request -> request.requestMatchers("register","login").permitAll().anyRequest().authenticated());
		//This will authorize every requests that are coming in but still we will not get the login form until we do the below step
//		http.formLogin(Customizer.withDefaults());
		//This will bring the sign in form whenever any request is hit but if we try using Postman it will still fail to get the data, because it will return the login form, to make this work for postman, we will need to add this below line
//		http.httpBasic(Customizer.withDefaults());
		//To handle the CSRF, we can make the HTTP Stateless that is everytime we make any request then it will fetch a new Session ID and this will perfectly for Postman but not for web login, because after login the session ID will change and we will keep on getting the same page and to avoid this we will need to comment out the form login portion and then it will work for both
//		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		return http.build();
		http.csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/register", "/login").permitAll()
            .anyRequest().authenticated()
        )
        .httpBasic(Customizer.withDefaults()) // keep if you still want basic auth
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    
    return http.build();

	}
	
	/* But we need to use our own Authentication Provider by overriding the normal method instead of using this 
	@Bean 
	public UserDetailsService userDetailsService() {
		//Now we can define users in this way but the problem with this is that we are still not using Database for storing the users, so we need to somehow still store the data into the DB apart from this
		
		UserDetails user1=User
				.withDefaultPasswordEncoder()
				.username("srinjay")
				.password("Srinjay@13")
				.roles("USER")
				.build();
				
		//We can pass as many users as we want because this takes an var agrs as a parameter so we can define as many users
		return new InMemoryUserDetailsManager(user1);
	}
	*/
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
		//We are using B crypt password encoder to validate our users everytime
		provider.setUserDetailsService(userDetailsService);
		//We will need to create our own class named something that will implement UserDetailsService and inject its object in this
		return provider;
	}
	
	
	//For JWT token, we would need to grab a hold on the Authentication Manager and pass this on
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
}
