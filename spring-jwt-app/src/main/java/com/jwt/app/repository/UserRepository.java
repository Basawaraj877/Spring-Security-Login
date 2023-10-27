package com.jwt.app.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.jwt.app.entities.User;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

	public User findByEmail(String email);


	public List<User> findByAccountNonLockedFalseAndLockedUntilBefore(LocalDateTime now);


}
