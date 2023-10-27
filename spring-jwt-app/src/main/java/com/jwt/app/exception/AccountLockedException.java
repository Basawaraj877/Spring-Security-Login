package com.jwt.app.exception;

import org.springframework.security.authentication.InsufficientAuthenticationException;

public class AccountLockedException extends InsufficientAuthenticationException {
	 public AccountLockedException(String message) {
		 super(message);
	 }
}
