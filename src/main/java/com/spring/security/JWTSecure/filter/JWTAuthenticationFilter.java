package com.spring.security.JWTSecure.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.spring.security.JWTSecure.service.TokenAuthenticationService;

//For Authenticate Request with token in request

public class JWTAuthenticationFilter extends GenericFilterBean{

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)throws IOException, ServletException {

		System.out.println("JWTAuthenticationFilter.doFilter");

		Authentication authentication;
		try {
			authentication = TokenAuthenticationService.getAuthentication((HttpServletRequest) servletRequest);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (Exception e) {
			e.printStackTrace();
		}
		filterChain.doFilter(servletRequest, servletResponse);
	}
}