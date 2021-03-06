package com.spring.security.JWTSecure;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan({"com.spring.security"})
@SpringBootApplication
public class JwtSecureApplication  extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(JwtSecureApplication.class, args);
	}
	
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(JwtSecureApplication.class);
	}
	
}
