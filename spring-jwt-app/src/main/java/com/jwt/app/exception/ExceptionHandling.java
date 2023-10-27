package com.jwt.app.exception;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionHandling{

	@ExceptionHandler(AccountExpiredException.class)
	public ResponseEntity<Object> accountExpiredException(AccountExpiredException ex){
		return ResponseEntity.status(HttpStatusCode.valueOf(201)).body(ex.getMessage());
	}
	
	@ExceptionHandler(PasswordExpiredException.class)
	public ResponseEntity<Object> passwordExpiredException(PasswordExpiredException ex){
		return ResponseEntity.status(HttpStatusCode.valueOf(202)).body(ex.getMessage());
	}
	
	@ExceptionHandler(AccountLockedException.class)
	public ResponseEntity<Object> accountLockedExpiredException(AccountLockedException ex){
		return ResponseEntity.status(HttpStatusCode.valueOf(203)).body(ex.getMessage());
	}
	
	@ExceptionHandler(UserDisabledException.class)
	public ResponseEntity<Object> userDisabledException(UserDisabledException ex){
		return ResponseEntity.status(HttpStatusCode.valueOf(204)).body(ex.getMessage());
	}
	
	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<Object> exceptionHandler(BadCredentialsException ex) {
		return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(ex.getMessage());
	}
}
