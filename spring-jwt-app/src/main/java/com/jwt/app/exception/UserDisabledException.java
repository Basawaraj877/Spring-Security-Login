package com.jwt.app.exception;

import org.springframework.security.authentication.InsufficientAuthenticationException;

public class UserDisabledException extends InsufficientAuthenticationException{
	public UserDisabledException(String message) {
		super(message);
	}
}
