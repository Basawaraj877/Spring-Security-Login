package com.jwt.app.controllers;

import javax.security.sasl.AuthenticationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.app.entities.User;
import com.jwt.app.model.GenerateNewPassword;
import com.jwt.app.model.JwtRequest;
import com.jwt.app.model.JwtResponse;
import com.jwt.app.model.UserResponse;
import com.jwt.app.security.JwtHelper;
import com.jwt.app.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private UserService userService;

	@Autowired
	private JwtHelper helper;

	// private Logger logger = LoggerFactory.getLogger(AuthController.class);

	@PostMapping("/login")
	public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) throws AuthenticationException {

		JwtResponse response = userService.userLogin(request.getEmail(), request.getPassword());

		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@PostMapping("/save")
	public ResponseEntity<Object> save(@RequestBody User user) {
		Object userFound = userService.createUser(user);

		return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(userFound);
	}

	@GetMapping("/get-user")
	public UserResponse getUser() {
		UserResponse userResponse = userService.findUser();
		return userResponse;
	}

	@PutMapping("/new-password")
	public ResponseEntity<String> newPassword(@RequestBody GenerateNewPassword newPasswrod) {
		String message = userService.changePassword(newPasswrod);
		return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(message);
	}
	
	@DeleteMapping("/delete-user")
	public String delete() {
		return null;
	}
}
