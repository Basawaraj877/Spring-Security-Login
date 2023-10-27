package com.jwt.app.security;

import java.io.IOException;
import java.io.PrintWriter;

import org.apache.logging.log4j.Logger;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomJwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private org.slf4j.Logger logger = LoggerFactory.getLogger(Authentication.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		int http = response.getStatus();

		logger.info("HTTP Code " + http + " Auth Exception " + authException.getClass().getName() + " Message "
				+ authException.getMessage());
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

		PrintWriter out = response.getWriter();
		out.println("Access Denied " + authException.getMessage());

	}

}
