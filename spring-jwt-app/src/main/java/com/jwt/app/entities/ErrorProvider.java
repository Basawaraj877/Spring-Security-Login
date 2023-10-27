package com.jwt.app.entities;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties(prefix = "error")
public class ErrorProvider {
	private String accountExpired;
	private String passwordExpired;
	private String accountLocked;
	private String userDisabled;
}
