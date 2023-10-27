package com.jwt.app.exception;

import org.springframework.security.authentication.InsufficientAuthenticationException;

public class AccountExpiredException extends InsufficientAuthenticationException {
	public AccountExpiredException(String message) {
		super(message);
	}
}
