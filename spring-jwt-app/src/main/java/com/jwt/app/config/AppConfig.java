package com.jwt.app.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.jwt.app.entities.ErrorProvider;

@Configuration
public class AppConfig {
	
//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails user1=User.builder().username("Salman")
//				.password(this.passwordEncoder().encode("salman")).roles("ADMIN").build();
//		
//		UserDetails user2=User.builder().username("Vineeth").password(this.passwordEncoder().encode("vinnu")).roles("USER").build();
//		return new InMemoryUserDetailsManager(user1,user2);
//	}
	
	@Autowired
	private UserDetailsService userDetailsService;

	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration auth) throws Exception {
		return auth.getAuthenticationManager();
	}
	
	@Bean
	public DaoAuthenticationProvider daoProivder() {
		DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		provider.setPasswordEncoder(this.passwordEncoder());
		return provider;
	}
	
	@Bean
	public ErrorProvider errorProvider() {
		return new ErrorProvider();
	}
}
