package com.jwt.app.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GenerateNewPassword {
	private String oldPassword;
	private String newPassword;

}
