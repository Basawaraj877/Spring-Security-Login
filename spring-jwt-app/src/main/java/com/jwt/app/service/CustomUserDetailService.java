package com.jwt.app.service;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwt.app.entities.User;
import com.jwt.app.exception.UserDisabledException;
import com.jwt.app.repository.UserRepository;

@Service
public class CustomUserDetailService implements UserDetailsService, UserDetails {

	private Logger logger = LoggerFactory.getLogger(UserDetailsService.class);

	@Autowired
	private UserRepository userRepo;
	private User user;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		user = userRepo.findByEmail(email);
		if (user == null) {
			throw new UsernameNotFoundException("User not Found with user name " + email);
		}

		int maxLoginAttempts = 3;
		if (user.getFailedLoginAttempts() >= maxLoginAttempts && user.getLockedUntil() == null) {
			LocalDateTime now = LocalDateTime.now();
			LocalDateTime lockedUntil = now.plusMinutes(2);
			user.setLockedUntil(lockedUntil);
			user.setAccountNonLocked(false);
			userRepo.save(user);
			// user.isAccountNonLocked();
		}
		if (!user.isAccountNonLocked()) {
			throw new LockedException("Account locked  --> CustomUserDetailsService");
		}
		if (!user.isEnabled()) {
			throw new UserDisabledException("Account De-activated  -->  CustomUserDetailsService");
		}

		return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(),
				getAuthorities());
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return authorities;
	}

	@Override
	public String getPassword() {

		return user.getPassword();
	}

	@Override
	public String getUsername() {

		return user.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {

		if (user.getAccountExpiredDate() == null) {

			return true;
		} else {
			return !(user.getAccountExpiredDate().isBefore(LocalDateTime.now()));
		}
	}

	@Override
	public boolean isAccountNonLocked() {
		return user.isAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {

		if (user.getPasswordExpiredDate() == null) {
			return true;
		} else {
			boolean value = !(user.getPasswordExpiredDate().isBefore(LocalDateTime.now()));
			return value;
		}
	}

	@Override
	public boolean isEnabled() {

		return user.isEnabled();
	}

}
