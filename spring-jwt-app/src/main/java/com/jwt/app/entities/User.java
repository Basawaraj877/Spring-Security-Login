package com.jwt.app.entities;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
@ToString
@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "USER_TABLE")
public class User {

	@Id
	private String userId;
	private String userName;
	private String email;
	private String password;
	private LocalDateTime accountExpiredDate;
	private boolean accountNonLocked;
	private LocalDateTime passwordExpiredDate;
	private boolean enabled;
	private int failedLoginAttempts;
	private LocalDateTime lockedUntil;

}
