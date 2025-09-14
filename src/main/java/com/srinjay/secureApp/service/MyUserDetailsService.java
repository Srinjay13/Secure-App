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
public class MyUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UserRepo repo;
	// We will need to use the Repo because we will need to use the DB to be used

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Users user = repo.findByUsername(username);
		if(user==null) {
			System.out.println("User Not Found");
			throw new UsernameNotFoundException(username+" not found");
		}
		
		return new UserPrincipal(user);
	}

}
