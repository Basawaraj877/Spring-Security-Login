package com.jwt.app.service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.jwt.app.entities.User;
import com.jwt.app.exception.AccountLockedException;
import com.jwt.app.exception.UserDisabledException;
import com.jwt.app.model.JwtResponse;
import com.jwt.app.model.GenerateNewPassword;
import com.jwt.app.model.UserResponse;
import com.jwt.app.repository.UserRepository;
import com.jwt.app.security.JwtHelper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class UserService {

	@Autowired
	private UserRepository userRepo;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtHelper helper;

	@Autowired
	private AuthenticationManager manager;

	@Autowired
	private HttpServletRequest request;

	public String getUserName() {
		String header = this.request.getHeader("Authorization");
		String token = header.substring(7);
		return this.helper.getUsernameFromToken(token);
	}

	public List<User> getUsers() {
		return userRepo.findAll();
	}

	public Object createUser(User user) {

		LocalDateTime currentDate = LocalDateTime.now();
		User userDB = userRepo.findByEmail(user.getEmail());
		
		if (userDB == null) {
			user.setUserId(UUID.randomUUID().toString());
			user.setPassword(passwordEncoder.encode(user.getPassword()));
			user.setAccountExpiredDate(currentDate.plus(5, ChronoUnit.DAYS));
			user.setPasswordExpiredDate(currentDate.plus(30, ChronoUnit.DAYS));
			user.setAccountNonLocked(true);
			user.setEnabled(true);
			user.setFailedLoginAttempts(0);
			return userRepo.save(user);
		} else {
			return "User already existed with email id " + user.getEmail();
		}
	}

	public UserResponse findUser() {
		User user = userRepo.findByEmail(this.getUserName());
		UserResponse userRes = new UserResponse();
		userRes.setUserName(user.getUserName());
		userRes.setEmail(user.getEmail());
		return userRes;
	}

	public JwtResponse userLogin(String email, String password) throws javax.security.sasl.AuthenticationException {

		UserDetails userDetails = userDetailsService.loadUserByUsername(email);
		
		this.doAuthenticate(email, password);

		String token = this.helper.generateToken(userDetails);

		JwtResponse response = JwtResponse.builder().jwtToken(token).build(); // .withUsername(userDetails.getUsername())
		return response;
	}

//	private boolean validateUserPassword(String rawPassword, String userPassword) {
//
//		return passwordEncoder.matches(rawPassword, userPassword);
//
//	}

	private void doAuthenticate(String email, String password) throws javax.security.sasl.AuthenticationException {

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
		try {
			manager.authenticate(authentication);

		} catch (BadCredentialsException e) {

			User user = userRepo.findByEmail(email);
			user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
			userRepo.save(user);

			throw new BadCredentialsException(" Invalid Username or Password  !!");
		} catch (LockedException e) {
			throw new LockedException("Account locked " + e.getMessage() + "  --> UserService");
		} catch (DisabledException e) {
			throw new DisabledException("Account Disabled " + e.getMessage() + "  --> UserService");
		} catch (AccountExpiredException e) {
			throw new AccountExpiredException("Account expired " + e.getMessage() + "  --> UserService");
		} catch (CredentialsExpiredException e) {
			throw new CredentialsExpiredException("Password expired " + e.getMessage() + " --> UserService");
		} catch (AuthenticationException e) {
			throw new javax.security.sasl.AuthenticationException(e.getMessage());
		}

	}

	public String changePassword(GenerateNewPassword generatePassword) {

		String oldPass = generatePassword.getOldPassword();
		String newPass = generatePassword.getNewPassword();

		User user = userRepo.findByEmail(this.getUserName());

		if (!passwordEncoder.matches(newPass, user.getPassword())) {
			if (passwordEncoder.matches(oldPass, user.getPassword())) {

				user.setPassword(passwordEncoder.encode(newPass));
				userRepo.save(user);

				return "Password changed successfully...";
			} else {
				return "Please enter currect password";
			}
		} else {
			return "New password should different from old password";
		}
	}
	
	@Scheduled(fixedRate = 60000)
	public void unlockAccounts() {
		LocalDateTime now=LocalDateTime.now();
		List<User> users=userRepo.findByAccountNonLockedFalseAndLockedUntilBefore(now);
		for(User user:users) {
			user.setAccountNonLocked(true);
			user.setLockedUntil(null);
			user.setFailedLoginAttempts(0);
			userRepo.save(user);
		}
	}

}
