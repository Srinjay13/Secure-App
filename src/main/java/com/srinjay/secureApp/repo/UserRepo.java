package com.srinjay.secureApp.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.srinjay.secureApp.model.Users;

public interface UserRepo extends JpaRepository<Users, Integer> {

    Users findByUsername(String username);
}
