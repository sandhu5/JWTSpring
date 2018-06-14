package com.spring.security.JWTSecure.filter;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.JWTSecure.service.TokenAuthenticationService;

//For Login

public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

	static String defaultUrl = "http://localhost:8080/PPL/swagger-ui.html";

	public JWTLoginFilter(String url, AuthenticationManager authManager) {
		super(new AntPathRequestMatcher(url));
		setAuthenticationManager(authManager);
	}
	
	public JWTLoginFilter() {
		super(defaultUrl);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

		String username = request.getParameter("username");
		String password = request.getParameter("password");

		return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList()));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		System.out.println("JWTLoginFilter.successfulAuthentication:");
		try {
			// Write Authorization to Headers of Response.
			TokenAuthenticationService.addAuthentication(response, authResult.getName());
			String authorizationString = response.getHeader("Authorization");

			ObjectMapper objectMapper = new ObjectMapper();
			objectMapper.writeValue(response.getWriter(), "JWT is " + authorizationString);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request,HttpServletResponse response, AuthenticationException failed)throws IOException, ServletException{
		ObjectMapper objectMapper = new ObjectMapper() ;
		objectMapper.writeValue(response.getWriter(), "Invalid Session/Token ");
	}
}
