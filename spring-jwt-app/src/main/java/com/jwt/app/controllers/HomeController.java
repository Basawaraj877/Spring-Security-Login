package com.jwt.app.controllers;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.app.entities.User;
import com.jwt.app.repository.UserRepository;
import com.jwt.app.security.JwtAuthenticationFilter;
import com.jwt.app.service.UserService;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/home")
public class HomeController {
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private SecurityFilterChain securityFilterChain;
	
	@Autowired
	private JwtAuthenticationFilter jwtFilter;
	
	@Autowired
	private HttpServletResponse response;
	
	@Autowired
	private UserRepository userRepo;
	
	
	@GetMapping("/user/{email}")
	public String getUser(@PathVariable String email) throws IOException {
        User user=userRepo.findByEmail(email);
		//PrintWriter out=response.getWriter();
		
        return user.toString();
		
		
	}
	
	@GetMapping("/users")
	public List<User> getUsers(){
		return userService.getUsers();
	}
	
//	@GetMapping("/find")
//	public void find(HttpServletRequest request,HttpServletResponse response,FilterChain filterChain) {
//		jwtFilter.doFilterInternal(request,response,filterChain);
//	}
}
